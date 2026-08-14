import { expect, test } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import type { Handler } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { TokenExtractor, TokenVerifier } from '../../src/token';
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

test('with invalid token', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: 'Bearer token-1' },
  });

  const [tokenExtractor, tokenExtractorMocks] = useFunctionMock<TokenExtractor>([
    { parameters: [serverRequest], return: 'token-1' },
  ]);

  const [tokenVerifier, tokenVerifierMocks] = useFunctionMock<TokenVerifier>([
    { parameters: ['token-1'], error: new Error('"exp" claim timestamp check failed') },
  ]);

  const [handler, handlerMocks] = useFunctionMock<Handler>([]);

  const middleware = createOidcAuthenticationMiddleware(tokenExtractor, tokenVerifier, 'api');

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.statusText).toBe('Unauthorized');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'www-authenticate':
      'Bearer realm="api", error="invalid_token", error_description="\'exp\' claim timestamp check failed"',
  });

  expect(tokenExtractorMocks).toHaveLength(0);
  expect(tokenVerifierMocks).toHaveLength(0);
  expect(handlerMocks).toHaveLength(0);
});

test('with invalid token and none error rejection', async () => {
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

  const response = await middleware(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.statusText).toBe('Unauthorized');
  expect(Object.fromEntries(response.headers.entries())).toEqual({
    'www-authenticate': 'Bearer error="invalid_token", error_description="unknown error"',
  });

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
