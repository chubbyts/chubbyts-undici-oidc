import { expect, test, vi } from 'vitest';
import { useFunctionMock } from '@chubbyts/chubbyts-function-mock/dist/function-mock';
import type { OidcConfiguration } from '../../src/discovery';
import { createOidcConfigurationResolver } from '../../src/discovery';

const issuer = 'https://issuer.example.com';
const url = 'https://issuer.example.com/.well-known/openid-configuration';

const configuration: OidcConfiguration = {
  issuer,
  jwks_uri: 'https://issuer.example.com/jwks',
  authorization_endpoint: 'https://issuer.example.com/authorize',
  token_endpoint: 'https://issuer.example.com/token',
};

test('resolve configuration', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    { parameters: [url], return: Promise.resolve(new Response(JSON.stringify(configuration))) },
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, fetch);

  expect(await oidcConfigurationResolver()).toEqual(configuration);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with default fetch', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    { parameters: [url], return: Promise.resolve(new Response(JSON.stringify(configuration))) },
  ]);

  vi.stubGlobal('fetch', fetch);

  try {
    const oidcConfigurationResolver = createOidcConfigurationResolver(issuer);

    expect(await oidcConfigurationResolver()).toEqual(configuration);
  } finally {
    vi.unstubAllGlobals();
  }

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with trailing slash issuer', async () => {
  const issuerWithTrailingSlash = 'https://issuer.example.com/';

  const configurationWithTrailingSlashIssuer: OidcConfiguration = {
    ...configuration,
    issuer: issuerWithTrailingSlash,
  };

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      parameters: [url],
      return: Promise.resolve(new Response(JSON.stringify(configurationWithTrailingSlashIssuer))),
    },
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuerWithTrailingSlash, fetch);

  expect(await oidcConfigurationResolver()).toEqual(configurationWithTrailingSlashIssuer);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with multiple trailing slashes issuer', async () => {
  const issuerWithTrailingSlashes = 'https://issuer.example.com//';

  const configurationWithTrailingSlashesIssuer: OidcConfiguration = {
    ...configuration,
    issuer: issuerWithTrailingSlashes,
  };

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      parameters: [url],
      return: Promise.resolve(new Response(JSON.stringify(configurationWithTrailingSlashesIssuer))),
    },
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuerWithTrailingSlashes, fetch);

  expect(await oidcConfigurationResolver()).toEqual(configurationWithTrailingSlashesIssuer);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with expiring cache', async () => {
  vi.useFakeTimers();

  try {
    const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
      { parameters: [url], return: Promise.resolve(new Response(JSON.stringify(configuration))) },
      { parameters: [url], return: Promise.resolve(new Response(JSON.stringify(configuration))) },
    ]);

    const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, fetch, 10);

    expect(await oidcConfigurationResolver()).toEqual(configuration);

    vi.advanceTimersByTime(9999);

    expect(await oidcConfigurationResolver()).toEqual(configuration);
    expect(fetchMocks).toHaveLength(1);

    vi.advanceTimersByTime(1);

    expect(await oidcConfigurationResolver()).toEqual(configuration);
    expect(fetchMocks).toHaveLength(0);
  } finally {
    vi.useRealTimers();
  }
});

test('resolve configuration with cache', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    { parameters: [url], return: Promise.resolve(new Response(JSON.stringify(configuration))) },
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, fetch);

  const resolvedConfiguration = await oidcConfigurationResolver();

  expect(resolvedConfiguration).toEqual(configuration);
  expect(await oidcConfigurationResolver()).toBe(resolvedConfiguration);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration without cache', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    { parameters: [url], return: Promise.resolve(new Response(JSON.stringify(configuration))) },
    { parameters: [url], return: Promise.resolve(new Response(JSON.stringify(configuration))) },
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, fetch, 0);

  expect(await oidcConfigurationResolver()).toEqual(configuration);
  expect(await oidcConfigurationResolver()).toEqual(configuration);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with failed response', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    { parameters: [url], return: Promise.resolve(new Response(undefined, { status: 404 })) },
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, fetch);

  await expect(oidcConfigurationResolver()).rejects.toThrow(
    'Cannot fetch oidc configuration from "https://issuer.example.com/.well-known/openid-configuration": status 404',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with issuer mismatch', async () => {
  const configurationWithOtherIssuer: OidcConfiguration = {
    ...configuration,
    issuer: 'https://other-issuer.example.com',
  };

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    { parameters: [url], return: Promise.resolve(new Response(JSON.stringify(configurationWithOtherIssuer))) },
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, fetch);

  await expect(oidcConfigurationResolver()).rejects.toThrow(
    'Issuer mismatch: expected "https://issuer.example.com", given "https://other-issuer.example.com"',
  );

  expect(fetchMocks).toHaveLength(0);
});
