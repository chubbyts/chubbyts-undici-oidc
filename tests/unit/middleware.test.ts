import { expect, test } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import { useObjectMock } from '@chubbyts/chubbyts-function-mock/dist/object-mock';
import type { Logger } from '@chubbyts/chubbyts-log-types/dist/log';
import type { Handler } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { TokenExtractor, TokenVerifier } from '../../src/token';
import { InvalidTokenError } from '../../src/error';
import { createOidcAuthenticationMiddleware } from '../../src/middleware';

test('without token, without realm', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource');

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: undefined },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.statusText).toBe('Unauthorized');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'www-authenticate': 'Bearer',
  });

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('without token, with realm', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource');

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: undefined },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier, 'api');

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.statusText).toBe('Unauthorized');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'www-authenticate': 'Bearer realm="api"',
  });

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test.each<{ name: string; realm: string; expectedChallenge: string }>([
  { name: 'double quotes', realm: 'my "api"', expectedChallenge: `Bearer realm="my 'api'"` },
  { name: 'backslashes', realm: 'my\\api\\', expectedChallenge: 'Bearer realm="myapi"' },
  { name: 'control characters', realm: 'my\r\napi\u0000\u007f', expectedChallenge: 'Bearer realm="myapi"' },
])('without token, with realm containing $name', async ({ realm, expectedChallenge }) => {
  const serverRequest = new ServerRequest('https://api.example.com/resource');

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: undefined },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier, realm);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.statusText).toBe('Unauthorized');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'www-authenticate': expectedChallenge,
  });

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with invalid token', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource?key=value', {
    headers: { authorization: 'Bearer token-1' },
  });

  const cause = new Error('"exp" claim timestamp check failed');

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: 'token-1' },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([
    { parameters: ['token-1'], error: new InvalidTokenError('"exp" claim timestamp check failed', cause) },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const [logger, loggerMocks] = useObjectMock<Logger>([
    {
      name: 'info',
      parameters: [
        'Invalid token',
        {
          method: 'GET',
          pathnameSearch: '/resource?key=value',
          error: { name: 'InvalidTokenError', message: '"exp" claim timestamp check failed', cause },
        },
      ],
    },
  ]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier, 'api', logger);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.statusText).toBe('Unauthorized');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'www-authenticate':
      'Bearer realm="api", error="invalid_token", error_description="The access token is invalid or expired"',
  });

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
  expect(loggerMocks).toHaveLength(0);
});

test('with invalid token, without realm and default logger', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: 'Bearer token-1' },
  });

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: 'token-1' },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([
    { parameters: ['token-1'], error: new InvalidTokenError('Invalid Compact JWS') },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier);

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.statusText).toBe('Unauthorized');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'www-authenticate': 'Bearer error="invalid_token", error_description="The access token is invalid or expired"',
  });

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with failing token verifier', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: 'Bearer token-1' },
  });

  const error = new Error('Cannot fetch oidc configuration from "https://issuer.example.com": status 500');

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: 'token-1' },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([{ parameters: ['token-1'], error }]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const [logger, loggerMocks] = useObjectMock<Logger>([]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier, 'api', logger);

  await expect(middleware(serverRequest, handler)).rejects.toBe(error);

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
  expect(loggerMocks).toHaveLength(0);
});

test('with failing token verifier and none error rejection', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: 'Bearer token-1' },
  });

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: 'token-1' },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([
    {
      callback: async (): ReturnType<TokenVerifier> => {
        return Promise.reject('some none error rejection');
      },
    },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier);

  await expect(middleware(serverRequest, handler)).rejects.toBe('some none error rejection');

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with valid token', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: 'Bearer token-1' },
    attributes: { key: 'value' },
  });

  const claims = { iss: 'https://issuer.example.com', sub: 'subject-1' };

  const handlerResponse = new Response('OK');

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: 'token-1' },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([
    { parameters: ['token-1'], return: Promise.resolve(claims) },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([
    {
      callback: async (handledServerRequest: ServerRequest): Promise<Response> => {
        expect(handledServerRequest).not.toBe(serverRequest);
        expect(handledServerRequest.url).toBe(serverRequest.url);
        expect(handledServerRequest.attributes).toEqual({
          key: 'value',
          oidc: { token: 'token-1', claims },
        });

        return handlerResponse;
      },
    },
  ]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier);

  const response = await middleware(serverRequest, handler);

  expect(response).toBe(handlerResponse);

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with valid token and handler throwing invalid token error', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: 'Bearer token-1' },
  });

  const claims = { iss: 'https://issuer.example.com', sub: 'subject-1' };

  // an InvalidTokenError thrown behind the middleware is not a verification failure and must not become a 401
  const error = new InvalidTokenError('thrown by the handler');

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: 'token-1' },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([
    { parameters: ['token-1'], return: Promise.resolve(claims) },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([
    {
      callback: async (): Promise<Response> => {
        throw error;
      },
    },
  ]);

  const [logger, loggerMocks] = useObjectMock<Logger>([]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier, 'api', logger);

  await expect(middleware(serverRequest, handler)).rejects.toBe(error);

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
  expect(loggerMocks).toHaveLength(0);
});
