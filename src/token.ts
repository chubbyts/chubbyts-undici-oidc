import type { JWTPayload } from 'jose';
import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose';
import type { ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { OidcConfigurationResolver } from './discovery.js';

export type TokenExtractor = (request: ServerRequest) => string | undefined;

export const createBearerTokenExtractor = (): TokenExtractor => {
  return (request: ServerRequest): string | undefined => {
    const match = /^Bearer +(\S+)$/i.exec(String(request.headers.get('authorization')));

    return match ? match[1] : undefined;
  };
};

export type TokenVerifier = (token: string) => Promise<JWTPayload>;

export type JwtTokenVerifierOptions = {
  audience?: string | Array<string>;
  algorithms?: Array<string>;
  clockTolerance?: number;
  fetch?: typeof globalThis.fetch;
};

type JwkSetResolver = ReturnType<typeof createRemoteJWKSet>;

export const createJwtTokenVerifier = (
  oidcConfigurationResolver: OidcConfigurationResolver,
  options: JwtTokenVerifierOptions = {},
): TokenVerifier => {
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

    const { payload } = await jwtVerify(token, resolveJwkSet(configuration.jwks_uri), {
      issuer: configuration.issuer,
      audience: options.audience,
      algorithms: options.algorithms,
      clockTolerance: options.clockTolerance,
    });

    return payload;
  };
};
