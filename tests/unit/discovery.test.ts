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

const createFetchMock = (
  expectedUrl: string,
  response: Response | (() => Promise<Response>),
): { callback: typeof globalThis.fetch } => ({
  callback: async (input, init) => {
    expect(String(input)).toBe(expectedUrl);
    expect(init?.signal).toBeInstanceOf(AbortSignal);

    return typeof response === 'function' ? response() : response;
  },
});

test('create resolver with invalid issuer', () => {
  expect(() => createOidcConfigurationResolver('issuer.example.com')).toThrow(
    'Invalid issuer "issuer.example.com": must be an absolute url',
  );
});

test('resolve configuration', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(url, new Response(JSON.stringify(configuration))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch });

  expect(await oidcConfigurationResolver()).toEqual(configuration);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with default fetch', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(url, new Response(JSON.stringify(configuration))),
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
    createFetchMock(url, new Response(JSON.stringify(configurationWithTrailingSlashIssuer))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuerWithTrailingSlash, { fetch });

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
    createFetchMock(url, new Response(JSON.stringify(configurationWithTrailingSlashesIssuer))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuerWithTrailingSlashes, { fetch });

  expect(await oidcConfigurationResolver()).toEqual(configurationWithTrailingSlashesIssuer);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with expiring cache', async () => {
  vi.useFakeTimers();

  try {
    const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
      createFetchMock(url, new Response(JSON.stringify(configuration))),
      createFetchMock(url, new Response(JSON.stringify(configuration))),
    ]);

    const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch, maxAge: 10 });

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
    createFetchMock(url, new Response(JSON.stringify(configuration))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch });

  const resolvedConfiguration = await oidcConfigurationResolver();

  expect(resolvedConfiguration).toEqual(configuration);
  expect(await oidcConfigurationResolver()).toBe(resolvedConfiguration);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration without cache', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(url, new Response(JSON.stringify(configuration))),
    createFetchMock(url, new Response(JSON.stringify(configuration))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch, maxAge: 0 });

  expect(await oidcConfigurationResolver()).toEqual(configuration);
  expect(await oidcConfigurationResolver()).toEqual(configuration);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with failed response', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(url, new Response(undefined, { status: 404 })),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch });

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
    createFetchMock(url, new Response(JSON.stringify(configurationWithOtherIssuer))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch });

  await expect(oidcConfigurationResolver()).rejects.toThrow(
    'Issuer mismatch: expected "https://issuer.example.com", given "https://other-issuer.example.com"',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with timeout', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    {
      callback: async (_input, init) => {
        const signal = init?.signal as AbortSignal;

        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(signal.reason as Error));
        });
      },
    },
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch, timeout: 0.01 });

  const error: unknown = await oidcConfigurationResolver().then(
    () => undefined,
    (e: unknown) => e,
  );

  expect(error).toBeInstanceOf(Error);
  expect((error as Error).message).toBe(
    'Cannot fetch oidc configuration from "https://issuer.example.com/.well-known/openid-configuration": timeout after 0.01s',
  );
  expect(((error as Error).cause as Error).name).toBe('TimeoutError');

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with unreachable issuer', async () => {
  const fetchError = new TypeError('fetch failed');

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(url, () => Promise.reject(fetchError)),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch });

  await expect(oidcConfigurationResolver()).rejects.toBe(fetchError);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration concurrently', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(url, new Response(JSON.stringify(configuration))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch });

  const [first, second, third] = await Promise.all([
    oidcConfigurationResolver(),
    oidcConfigurationResolver(),
    oidcConfigurationResolver(),
  ]);

  expect(first).toEqual(configuration);
  expect(second).toBe(first);
  expect(third).toBe(first);

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration concurrently with failure', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(url, new Response(undefined, { status: 500 })),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch });

  const results = await Promise.allSettled([oidcConfigurationResolver(), oidcConfigurationResolver()]);

  expect(results).toHaveLength(2);

  for (const result of results) {
    expect(result.status).toBe('rejected');
    expect((result as PromiseRejectedResult).reason).toBeInstanceOf(Error);
    expect(((result as PromiseRejectedResult).reason as Error).message).toBe(
      'Cannot fetch oidc configuration from "https://issuer.example.com/.well-known/openid-configuration": status 500',
    );
  }

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with failure cooldown', async () => {
  vi.useFakeTimers();

  try {
    const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
      createFetchMock(url, new Response(undefined, { status: 500 })),
      createFetchMock(url, new Response(JSON.stringify(configuration))),
    ]);

    const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch, cooldown: 10 });

    const firstError: unknown = await oidcConfigurationResolver().then(
      () => undefined,
      (e: unknown) => e,
    );

    expect(firstError).toBeInstanceOf(Error);
    expect((firstError as Error).message).toBe(
      'Cannot fetch oidc configuration from "https://issuer.example.com/.well-known/openid-configuration": status 500',
    );

    vi.advanceTimersByTime(9999);

    // within cooldown: same error, no fetch
    await expect(oidcConfigurationResolver()).rejects.toBe(firstError);
    expect(fetchMocks).toHaveLength(1);

    vi.advanceTimersByTime(1);

    // after cooldown: fetch again, success clears the failure
    expect(await oidcConfigurationResolver()).toEqual(configuration);
    expect(await oidcConfigurationResolver()).toEqual(configuration);
    expect(fetchMocks).toHaveLength(0);
  } finally {
    vi.useRealTimers();
  }
});

test('resolve configuration without failure cooldown', async () => {
  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(url, new Response(undefined, { status: 500 })),
    createFetchMock(url, new Response(JSON.stringify(configuration))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch, cooldown: 0 });

  await expect(oidcConfigurationResolver()).rejects.toThrow('status 500');
  expect(await oidcConfigurationResolver()).toEqual(configuration);

  expect(fetchMocks).toHaveLength(0);
});

test.each<{ name: string; givenIssuer: string; jwks_uri: unknown }>([
  { name: 'https issuer and invalid jwks_uri', givenIssuer: 'https://issuer.example.com', jwks_uri: 'not-a-url' },
  { name: 'https issuer and missing jwks_uri', givenIssuer: 'https://issuer.example.com', jwks_uri: undefined },
  { name: 'http issuer and invalid jwks_uri', givenIssuer: 'http://issuer.example.com', jwks_uri: 'not-a-url' },
  { name: 'http issuer and missing jwks_uri', givenIssuer: 'http://issuer.example.com', jwks_uri: undefined },
])('resolve configuration with $name', async ({ givenIssuer, jwks_uri }) => {
  const invalidConfiguration = { ...configuration, issuer: givenIssuer, jwks_uri };

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(
      `${givenIssuer}/.well-known/openid-configuration`,
      new Response(JSON.stringify(invalidConfiguration)),
    ),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(givenIssuer, { fetch });

  await expect(oidcConfigurationResolver()).rejects.toThrow(
    `Missing or invalid jwks_uri "${String(jwks_uri)}" for issuer "${givenIssuer}"`,
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with https issuer and http jwks_uri', async () => {
  const insecureConfiguration = { ...configuration, jwks_uri: 'http://issuer.example.com/jwks' };

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(url, new Response(JSON.stringify(insecureConfiguration))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(issuer, { fetch });

  await expect(oidcConfigurationResolver()).rejects.toThrow(
    'Insecure jwks_uri "http://issuer.example.com/jwks" for https issuer "https://issuer.example.com"',
  );

  expect(fetchMocks).toHaveLength(0);
});

test('resolve configuration with http issuer and http jwks_uri', async () => {
  const httpIssuer = 'http://issuer.example.com';
  const httpUrl = 'http://issuer.example.com/.well-known/openid-configuration';

  const httpConfiguration: OidcConfiguration = {
    ...configuration,
    issuer: httpIssuer,
    jwks_uri: 'http://issuer.example.com/jwks',
  };

  const [fetch, fetchMocks] = useFunctionMock<typeof globalThis.fetch>([
    createFetchMock(httpUrl, new Response(JSON.stringify(httpConfiguration))),
  ]);

  const oidcConfigurationResolver = createOidcConfigurationResolver(httpIssuer, { fetch });

  expect(await oidcConfigurationResolver()).toEqual(httpConfiguration);

  expect(fetchMocks).toHaveLength(0);
});
