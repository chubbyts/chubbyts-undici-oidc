import type { CryptoKey, FlattenedJWSInput, JWSHeaderParameters, JWTPayload, JWTVerifyGetKey } from 'jose';
import { createLocalJWKSet, createRemoteJWKSet, customFetch, errors, jwtVerify } from 'jose';
import type { ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { OidcConfigurationResolver } from './discovery.js';
import { InvalidTokenError } from './error.js';

export type TokenExtractor = (request: ServerRequest) => string | undefined;

export const createBearerTokenExtractor = (): TokenExtractor => {
  return (request: ServerRequest): string | undefined => {
    const match = /^Bearer +(\S+)$/i.exec(String(request.headers.get('authorization')));

    return match ? match[1] : undefined;
  };
};

export type TokenVerifier = (token: string) => Promise<JWTPayload>;

export type JwtTokenVerifierOptions = {
  audience: string | Array<string>;
  algorithms?: Array<string>;
  clockTolerance?: number;
  typ?: string;
  requiredClaims?: Array<string>;
  fetch?: typeof globalThis.fetch;
  jwksMaxAge?: number;
  jwksTimeout?: number;
  jwksCooldown?: number;
};

const isNonEmptyString = (value: unknown): value is string => typeof value === 'string' && value !== '';

const isNonEmptyAudience = (value: unknown): value is string | Array<string> => {
  return isNonEmptyString(value) || (Array.isArray(value) && value.length > 0 && value.every(isNonEmptyString));
};

const isTokenError = (error: unknown): error is errors.JOSEError => {
  return (
    error instanceof errors.JWTInvalid ||
    error instanceof errors.JWSInvalid ||
    error instanceof errors.JWTExpired ||
    error instanceof errors.JWTClaimValidationFailed ||
    error instanceof errors.JOSEAlgNotAllowed ||
    error instanceof errors.JOSENotSupported ||
    error instanceof errors.JWKSNoMatchingKey ||
    // ambiguous key selection (e.g. token without "kid" against a jwks with multiple keys of the same alg): the token
    // cannot be verified, treat it like a token without a matching key instead of an internal error
    error instanceof errors.JWKSMultipleMatchingKeys ||
    error instanceof errors.JWSSignatureVerificationFailed
  );
};

export const createJwtTokenVerifier = (
  oidcConfigurationResolver: OidcConfigurationResolver,
  options: JwtTokenVerifierOptions,
): TokenVerifier => {
  // typescript enforces the audience, but a runtime check protects javascript consumers (or a misconfigured
  // "undefined") from silently skipping the audience check and accepting any token of the issuer
  if (!isNonEmptyAudience(options.audience)) {
    throw new Error('Invalid audience: must be a non-empty string or a non-empty array of non-empty strings');
  }

  // "iss" and "aud" get required by jose through the issuer / audience options, "exp" needs to be required explicitly,
  // otherwise a token without expiration would be valid forever
  const requiredClaims = ['exp', ...(options.requiredClaims ?? [])];

  const { jwksMaxAge = 600, jwksTimeout = 5, jwksCooldown = 30 } = options;

  const createJwkSetResolver = (jwksUri: string): JWTVerifyGetKey => {
    const remoteJwkSet = createRemoteJWKSet(new URL(jwksUri), {
      ...(options.fetch ? { [customFetch]: options.fetch } : {}),
      cacheMaxAge: jwksMaxAge * 1000,
      timeoutDuration: jwksTimeout * 1000,
      cooldownDuration: jwksCooldown * 1000,
    });

    // oxlint-disable-next-line functional/no-let
    let failure: { error: unknown; retryAfter: number } | undefined;

    // a jwks outage should not take the resource server down: jose does not serve a stale jwks once its cache expired,
    // so verify against the last known keys (if there ever were any) instead of failing
    const resolveStaleKey = async (
      protectedHeader: JWSHeaderParameters,
      token: FlattenedJWSInput,
      error: unknown,
    ): Promise<CryptoKey> => {
      const jwks = remoteJwkSet.jwks();

      if (jwks) {
        return createLocalJWKSet(jwks)(protectedHeader, token);
      }

      throw error;
    };

    return async (protectedHeader: JWSHeaderParameters, token: FlattenedJWSInput): Promise<CryptoKey> => {
      // fail fast (or serve stale) during an outage instead of hitting the jwks uri with every request
      if (failure && failure.retryAfter > Date.now()) {
        return resolveStaleKey(protectedHeader, token, failure.error);
      }

      try {
        return await remoteJwkSet(protectedHeader, token);
      } catch (error) {
        if (isTokenError(error)) {
          throw error;
        }

        failure = { error, retryAfter: Date.now() + jwksCooldown * 1000 };

        return resolveStaleKey(protectedHeader, token, error);
      }
    };
  };

  // oxlint-disable-next-line functional/no-let
  let cache: { jwksUri: string; jwkSetResolver: JWTVerifyGetKey } | undefined;

  const resolveJwkSet = (jwksUri: string): JWTVerifyGetKey => {
    if (cache?.jwksUri === jwksUri) {
      return cache.jwkSetResolver;
    }

    const jwkSetResolver = createJwkSetResolver(jwksUri);

    // oxlint-disable-next-line functional/immutable-data
    cache = { jwksUri, jwkSetResolver };

    return jwkSetResolver;
  };

  return async (token: string): Promise<JWTPayload> => {
    const configuration = await oidcConfigurationResolver();

    try {
      const { payload } = await jwtVerify(token, resolveJwkSet(configuration.jwks_uri), {
        issuer: configuration.issuer,
        audience: options.audience,
        algorithms: options.algorithms,
        clockTolerance: options.clockTolerance,
        typ: options.typ,
        requiredClaims,
      });

      return payload;
    } catch (error) {
      if (isTokenError(error)) {
        throw new InvalidTokenError(error.message, error);
      }

      throw error;
    }
  };
};
