import type { JWTPayload } from 'jose';
import type { Handler, Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { TokenExtractor, TokenVerifier } from './token.js';

export type OidcAttributes = {
  oidc: {
    token: string;
    claims: JWTPayload;
  };
};

const formatChallengeParameter = ([key, value]: [string, string]): string => {
  return ` ${key}="${value.replaceAll('"', "'")}"`;
};

const createChallenge = (realm: string | undefined, parameters: Record<string, string>): string => {
  const allParameters = Object.entries({ ...(realm ? { realm } : {}), ...parameters });

  return `Bearer${allParameters.map(formatChallengeParameter).join(',')}`;
};

const createUnauthorizedResponse = (challenge: string): Response => {
  return new Response(undefined, {
    status: 401,
    statusText: 'Unauthorized',
    headers: { 'www-authenticate': challenge },
  });
};

export const createOidcAuthenticationMiddleware = (
  tokenExtractor: TokenExtractor,
  tokenVerifier: TokenVerifier,
  realm?: string,
): Middleware => {
  return async (request: ServerRequest, handler: Handler): Promise<Response> => {
    const token = tokenExtractor(request);

    if (!token) {
      return createUnauthorizedResponse(createChallenge(realm, {}));
    }

    try {
      const claims = await tokenVerifier(token);

      return await handler(
        new ServerRequest(request, { attributes: { ...request.attributes, oidc: { token, claims } } }),
      );
    } catch (error) {
      return createUnauthorizedResponse(
        createChallenge(realm, {
          error: 'invalid_token',
          error_description: error instanceof Error ? error.message : 'unknown error',
        }),
      );
    }
  };
};
