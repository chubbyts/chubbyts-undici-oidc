import type { JWTPayload } from 'jose';
import type { Logger } from '@chubbyts/chubbyts-log-types/dist/log';
import { createLogger } from '@chubbyts/chubbyts-log-types/dist/log';
import type { Handler, Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import { InvalidTokenError } from './error.js';
import type { TokenExtractor, TokenVerifier } from './token.js';

export type OidcAttributes = {
  oidc: {
    token: string;
    claims: JWTPayload;
  };
};

// quoted-string (rfc 7230): a backslash escapes the next char and control chars are not allowed at all (crlf would
// even make the header construction throw), so drop them and downgrade double quotes to single quotes
const sanitizeChallengeValue = (value: string): string => {
  // oxlint-disable-next-line no-control-regex
  return value.replaceAll(/[\\\u0000-\u001f\u007f]/g, '').replaceAll('"', "'");
};

const formatChallengeParameter = ([key, value]: [string, string]): string => {
  return ` ${key}="${sanitizeChallengeValue(value)}"`;
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

const resolvePathnameSearch = (url: URL): string => `${url.pathname}${url.search}`;

export const createOidcAuthenticationMiddleware = (
  tokenExtractor: TokenExtractor,
  tokenVerifier: TokenVerifier,
  realm?: string,
  logger: Logger = createLogger(),
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
      if (!(error instanceof InvalidTokenError)) {
        throw error;
      }

      logger.info('Invalid token', {
        method: request.method,
        pathnameSearch: resolvePathnameSearch(new URL(request.url)),
        error: { name: error.name, message: error.message, cause: error.cause },
      });

      // do not reflect the verification error to the client: it may leak internal details (issuer, jwks uri, ...)
      return createUnauthorizedResponse(
        createChallenge(realm, {
          error: 'invalid_token',
          error_description: 'The access token is invalid or expired',
        }),
      );
    }
  };
};
