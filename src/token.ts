import type { JWTPayload } from 'jose';
import { createRemoteJWKSet, customFetch, errors, jwtVerify } from 'jose';
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
};

type JwkSetResolver = ReturnType<typeof createRemoteJWKSet>;

const isTokenError = (error: unknown): error is errors.JOSEError => {
  return (
    error instanceof errors.JWTInvalid ||
    error instanceof errors.JWSInvalid ||
    error instanceof errors.JWTExpired ||
    error instanceof errors.JWTClaimValidationFailed ||
    error instanceof errors.JOSEAlgNotAllowed ||
    error instanceof errors.JOSENotSupported ||
    error instanceof errors.JWKSNoMatchingKey ||
    error instanceof errors.JWSSignatureVerificationFailed
  );
};

export const createJwtTokenVerifier = (
  oidcConfigurationResolver: OidcConfigurationResolver,
  options: JwtTokenVerifierOptions,
): TokenVerifier => {
  // "iss" and "aud" get required by jose through the issuer / audience options, "exp" needs to be required explicitly,
  // otherwise a token without expiration would be valid forever
  const requiredClaims = ['exp', ...(options.requiredClaims ?? [])];

  // oxlint-disable-next-line functional/no-let
  let cache: { jwksUri: string; jwkSetResolver: JwkSetResolver } | undefined;

  const resolveJwkSet = (jwksUri: string): JwkSetResolver => {
    if (cache?.jwksUri === jwksUri) {
      return cache.jwkSetResolver;
    }

    const jwkSetResolver = options.fetch
      ? createRemoteJWKSet(new URL(jwksUri), { [customFetch]: options.fetch })
      : createRemoteJWKSet(new URL(jwksUri));

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
