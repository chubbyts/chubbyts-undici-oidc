import type { KeyObject } from 'node:crypto';
import { expect, test } from 'vitest';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import { ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { OidcConfiguration, OidcConfigurationResolver } from '../../src/discovery';
import { createBearerTokenExtractor, createJwtTokenVerifier } from '../../src/token';

test.each<{ name: string; authorization: string | undefined; expectedToken: string | undefined }>([
  { name: 'without authorization header', authorization: undefined, expectedToken: undefined },
  { name: 'with other authorization scheme', authorization: 'Basic dXNlcjpwYXNzd29yZA==', expectedToken: undefined },
  { name: 'without token', authorization: 'Bearer', expectedToken: undefined },
  { name: 'with invalid token', authorization: 'Bearer some token', expectedToken: undefined },
  { name: 'with prefixed authorization header', authorization: 'prefix Bearer some-token', expectedToken: undefined },
  { name: 'with token', authorization: 'Bearer some-token', expectedToken: 'some-token' },
  {
    name: 'with multiple spaces between scheme and token',
    authorization: 'Bearer   some-token',
    expectedToken: 'some-token',
  },
  { name: 'with lowercase scheme', authorization: 'bearer some-token', expectedToken: 'some-token' },
])('extract token $name', ({ authorization, expectedToken }) => {
  const serverRequest = new ServerRequest('https://api.example.com/resource', {
    headers: authorization === undefined ? {} : { authorization },
  });

  const tokenExtractor = createBearerTokenExtractor();

  expect(tokenExtractor(serverRequest)).toBe(expectedToken);
});

const issuer = 'https://issuer.example.com';
const jwksUri = 'https://issuer.example.com/jwks';

const configuration: OidcConfiguration = {
  issuer,
  jwks_uri: jwksUri,
};

const createKeyAndJwks = async (): Promise<{ privateKey: KeyObject; jwks: unknown }> => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');

  const jwk = await exportJWK(publicKey);

  return { privateKey, jwks: { keys: [{ ...jwk, kid: 'key-1', alg: 'RS256', use: 'sig' }] } };
};

const createToken = async (
  privateKey: KeyObject,
  { iss, aud, iat }: { iss?: string; aud?: string; iat?: number } = {},
): Promise<string> => {
  const signJwt = new SignJWT({ scope: 'openid' })
    .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
    .setSubject('subject-1')
    .setIssuer(iss ?? issuer)
    .setAudience(aud ?? 'audience-1')
    .setIssuedAt(iat)
    .setExpirationTime((iat ?? Math.floor(Date.now() / 1000)) + 300);

  return signJwt.sign(privateKey);
};

const createJwksResponse = (jwks: unknown): Response => {
  return new Response(JSON.stringify(jwks), { headers: { 'content-type': 'application/json' } });
};

test('verify token', async () => {
  const { privateKey, jwks } = await createKeyAndJwks();

  const token = await createToken(privateKey);

  const [oidcConfigurationResolver, oidcConfigurationResolverMocks] = useFunctionMock<OidcConfigurationResolver>([
    { parameters: [], return: Promise.resolve(configuration) },
  ]);

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      callback: async (input) => {
        expect(String(input)).toBe(jwksUri);

        return createJwksResponse(jwks);
      },
    },
  ]);

  const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver, { audience: 'audience-1', fetch });

  expect(await tokenVerifier(token)).toEqual(
    expect.objectContaining({ iss: issuer, aud: 'audience-1', sub: 'subject-1', scope: 'openid' }),
  );

  expect(oidcConfigurationResolverMocks).toHaveLength(0);
  expect(fetchMocks).toHaveLength(0);
});

test('verify token with cached jwk set', async () => {
  const { privateKey, jwks } = await createKeyAndJwks();

  const token = await createToken(privateKey);

  const [oidcConfigurationResolver, oidcConfigurationResolverMocks] = useFunctionMock<OidcConfigurationResolver>([
    { parameters: [], return: Promise.resolve(configuration) },
    { parameters: [], return: Promise.resolve(configuration) },
  ]);

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      callback: async (input) => {
        expect(String(input)).toBe(jwksUri);

        return createJwksResponse(jwks);
      },
    },
  ]);

  const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver, { audience: 'audience-1', fetch });

  expect(await tokenVerifier(token)).toEqual(expect.objectContaining({ sub: 'subject-1' }));
  expect(await tokenVerifier(token)).toEqual(expect.objectContaining({ sub: 'subject-1' }));

  expect(oidcConfigurationResolverMocks).toHaveLength(0);
  expect(fetchMocks).toHaveLength(0);
});

test('verify token with changed jwks uri', async () => {
  const otherJwksUri = 'https://issuer.example.com/other-jwks';

  const { privateKey, jwks } = await createKeyAndJwks();

  const token = await createToken(privateKey);

  const [oidcConfigurationResolver, oidcConfigurationResolverMocks] = useFunctionMock<OidcConfigurationResolver>([
    { parameters: [], return: Promise.resolve(configuration) },
    { parameters: [], return: Promise.resolve({ ...configuration, jwks_uri: otherJwksUri }) },
  ]);

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      callback: async (input) => {
        expect(String(input)).toBe(jwksUri);

        return createJwksResponse(jwks);
      },
    },
    {
      callback: async (input) => {
        expect(String(input)).toBe(otherJwksUri);

        return createJwksResponse(jwks);
      },
    },
  ]);

  const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver, { audience: 'audience-1', fetch });

  expect(await tokenVerifier(token)).toEqual(expect.objectContaining({ sub: 'subject-1' }));
  expect(await tokenVerifier(token)).toEqual(expect.objectContaining({ sub: 'subject-1' }));

  expect(oidcConfigurationResolverMocks).toHaveLength(0);
  expect(fetchMocks).toHaveLength(0);
});

test('verify token with invalid issuer', async () => {
  const { privateKey, jwks } = await createKeyAndJwks();

  const token = await createToken(privateKey, { iss: 'https://other-issuer.example.com' });

  const [oidcConfigurationResolver, oidcConfigurationResolverMocks] = useFunctionMock<OidcConfigurationResolver>([
    { parameters: [], return: Promise.resolve(configuration) },
  ]);

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      callback: async () => createJwksResponse(jwks),
    },
  ]);

  const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver, { audience: 'audience-1', fetch });

  await expect(tokenVerifier(token)).rejects.toThrow('unexpected "iss" claim value');

  expect(oidcConfigurationResolverMocks).toHaveLength(0);
  expect(fetchMocks).toHaveLength(0);
});

test('verify token with invalid audience', async () => {
  const { privateKey, jwks } = await createKeyAndJwks();

  const token = await createToken(privateKey, { aud: 'audience-2' });

  const [oidcConfigurationResolver, oidcConfigurationResolverMocks] = useFunctionMock<OidcConfigurationResolver>([
    { parameters: [], return: Promise.resolve(configuration) },
  ]);

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      callback: async () => createJwksResponse(jwks),
    },
  ]);

  const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver, { audience: 'audience-1', fetch });

  await expect(tokenVerifier(token)).rejects.toThrow('unexpected "aud" claim value');

  expect(oidcConfigurationResolverMocks).toHaveLength(0);
  expect(fetchMocks).toHaveLength(0);
});

test('verify expired token', async () => {
  const { privateKey, jwks } = await createKeyAndJwks();

  const token = await createToken(privateKey, { iat: Math.floor(Date.now() / 1000) - 3600 });

  const [oidcConfigurationResolver, oidcConfigurationResolverMocks] = useFunctionMock<OidcConfigurationResolver>([
    { parameters: [], return: Promise.resolve(configuration) },
  ]);

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      callback: async () => createJwksResponse(jwks),
    },
  ]);

  const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver, { audience: 'audience-1', fetch });

  await expect(tokenVerifier(token)).rejects.toThrow('"exp" claim timestamp check failed');

  expect(oidcConfigurationResolverMocks).toHaveLength(0);
  expect(fetchMocks).toHaveLength(0);
});

test('verify expired token within clock tolerance', async () => {
  const { privateKey, jwks } = await createKeyAndJwks();

  const token = await createToken(privateKey, { iat: Math.floor(Date.now() / 1000) - 3600 });

  const [oidcConfigurationResolver, oidcConfigurationResolverMocks] = useFunctionMock<OidcConfigurationResolver>([
    { parameters: [], return: Promise.resolve(configuration) },
  ]);

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      callback: async () => createJwksResponse(jwks),
    },
  ]);

  const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver, {
    audience: 'audience-1',
    clockTolerance: 7200,
    fetch,
  });

  expect(await tokenVerifier(token)).toEqual(expect.objectContaining({ sub: 'subject-1' }));

  expect(oidcConfigurationResolverMocks).toHaveLength(0);
  expect(fetchMocks).toHaveLength(0);
});

test('verify token with not allowed algorithm', async () => {
  const { privateKey } = await createKeyAndJwks();

  const token = await createToken(privateKey);

  const [oidcConfigurationResolver, oidcConfigurationResolverMocks] = useFunctionMock<OidcConfigurationResolver>([
    { parameters: [], return: Promise.resolve(configuration) },
  ]);

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([]);

  const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver, {
    audience: 'audience-1',
    algorithms: ['ES256'],
    fetch,
  });

  await expect(tokenVerifier(token)).rejects.toThrow('"alg" (Algorithm) Header Parameter value not allowed');

  expect(oidcConfigurationResolverMocks).toHaveLength(0);
  expect(fetchMocks).toHaveLength(0);
});

test('verify invalid token with default options', async () => {
  const [oidcConfigurationResolver, oidcConfigurationResolverMocks] = useFunctionMock<OidcConfigurationResolver>([
    { parameters: [], return: Promise.resolve(configuration) },
  ]);

  const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver);

  await expect(tokenVerifier('invalid')).rejects.toThrow('Invalid Compact JWS');

  expect(oidcConfigurationResolverMocks).toHaveLength(0);
});
