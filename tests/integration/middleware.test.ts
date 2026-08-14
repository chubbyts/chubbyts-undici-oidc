import { Buffer } from 'node:buffer';
import { expect, test } from 'vitest';
import type { Handler, Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { JwtTokenVerifierOptions } from '../../src/token';
import { createBearerTokenExtractor, createJwtTokenVerifier } from '../../src/token';
import { createOidcConfigurationResolver } from '../../src/discovery';
import { createOidcAuthenticationMiddleware } from '../../src/middleware';

const issuer = `${process.env.MOCK_OAUTH2_SERVER_URL ?? 'http://localhost:8080'}/default`;

const fetchAccessToken = async (): Promise<string> => {
  const response = await fetch(`${issuer}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: 'api',
      client_secret: 'api-secret',
    }),
  });

  expect(response.status).toBe(200);

  const { access_token: accessToken } = (await response.json()) as { access_token: string };

  return accessToken;
};

const decodeClaims = (token: string): { aud: string | Array<string> } => {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()) as { aud: string | Array<string> };
};

const handler: Handler = async (serverRequest: ServerRequest): Promise<Response> => {
  return new Response(JSON.stringify(serverRequest.attributes.oidc), {
    headers: { 'content-type': 'application/json' },
  });
};

const createMiddleware = (options: JwtTokenVerifierOptions = {}): Middleware => {
  return createOidcAuthenticationMiddleware(
    createBearerTokenExtractor(),
    createJwtTokenVerifier(createOidcConfigurationResolver(issuer), options),
    'api',
  );
};

test('without token', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource');

  const response = await createMiddleware()(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.headers.get('www-authenticate')).toBe('Bearer realm="api"');
});

test('with invalid token', async () => {
  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: 'Bearer invalid-token' },
  });

  const response = await createMiddleware()(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.headers.get('www-authenticate')).toContain('Bearer realm="api", error="invalid_token"');
});

test('with valid token', async () => {
  const accessToken = await fetchAccessToken();

  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: `Bearer ${accessToken}` },
  });

  const response = await createMiddleware()(serverRequest, handler);

  expect(response.status).toBe(200);

  const oidc = (await response.json()) as { token: string; claims: { iss: string; sub: string } };

  expect(oidc.token).toBe(accessToken);
  expect(oidc.claims.iss).toBe(issuer);
  expect(oidc.claims.sub).toBe('api');
});

test('with valid token and matching audience', async () => {
  const accessToken = await fetchAccessToken();

  const { aud } = decodeClaims(accessToken);

  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: `Bearer ${accessToken}` },
  });

  const response = await createMiddleware({ audience: aud })(serverRequest, handler);

  expect(response.status).toBe(200);
});

test('with valid token and wrong audience', async () => {
  const accessToken = await fetchAccessToken();

  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: { authorization: `Bearer ${accessToken}` },
  });

  const response = await createMiddleware({ audience: 'https://other-api.example.com' })(serverRequest, handler);

  expect(response.status).toBe(401);
  expect(response.headers.get('www-authenticate')).toContain('error="invalid_token"');
  expect(response.headers.get('www-authenticate')).toContain('aud');
});
