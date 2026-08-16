export type OidcConfiguration = {
  issuer: string;
  jwks_uri: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
  [key: string]: unknown;
};

export type OidcConfigurationResolver = () => Promise<OidcConfiguration>;

export type OidcConfigurationResolverOptions = {
  fetch?: typeof globalThis.fetch;
  maxAge?: number;
  timeout?: number;
  cooldown?: number;
};

const stripTrailingSlashes = (value: string): string => {
  return value.endsWith('/') ? stripTrailingSlashes(value.slice(0, -1)) : value;
};

const isAbsoluteUrl = (value: unknown): boolean => URL.canParse(String(value));

const isHttpsUrl = (value: string): boolean => new URL(value).protocol === 'https:';

const isTimeoutError = (error: unknown): boolean => {
  return error instanceof Error && error.name === 'TimeoutError';
};

export const createOidcConfigurationResolver = (
  issuer: string,
  options: OidcConfigurationResolverOptions = {},
): OidcConfigurationResolver => {
  const { fetch = globalThis.fetch, maxAge = 3600, timeout = 5, cooldown = 30 } = options;

  if (!isAbsoluteUrl(issuer)) {
    throw new Error(`Invalid issuer "${issuer}": must be an absolute url`);
  }

  const url = `${stripTrailingSlashes(issuer)}/.well-known/openid-configuration`;

  // oxlint-disable-next-line functional/no-let
  let cache: { configuration: OidcConfiguration; validUntil: number } | undefined;

  // oxlint-disable-next-line functional/no-let
  let failure: { error: unknown; retryAfter: number } | undefined;

  // oxlint-disable-next-line functional/no-let
  let pending: Promise<OidcConfiguration> | undefined;

  const fetchConfiguration = async (): Promise<OidcConfiguration> => {
    const response = await fetch(url, { signal: AbortSignal.timeout(timeout * 1000) }).catch((error: unknown) => {
      if (isTimeoutError(error)) {
        throw new Error(`Cannot fetch oidc configuration from "${url}": timeout after ${timeout}s`, { cause: error });
      }

      throw error;
    });

    if (!response.ok) {
      throw new Error(`Cannot fetch oidc configuration from "${url}": status ${response.status}`);
    }

    const configuration = (await response.json()) as OidcConfiguration;

    if (configuration.issuer !== issuer) {
      throw new Error(`Issuer mismatch: expected "${issuer}", given "${configuration.issuer}"`);
    }

    // fail here with a clear message instead of an obscure error on the first token verification
    if (!isAbsoluteUrl(configuration.jwks_uri)) {
      throw new Error(`Missing or invalid jwks_uri "${String(configuration.jwks_uri)}" for issuer "${issuer}"`);
    }

    // a https issuer must not downgrade its keys to plain http (mitm on the jwks fetch means forged tokens)
    if (isHttpsUrl(issuer) && !isHttpsUrl(configuration.jwks_uri)) {
      throw new Error(`Insecure jwks_uri "${configuration.jwks_uri}" for https issuer "${issuer}"`);
    }

    return configuration;
  };

  // an issuer outage should not take the resource server down: keep serving the last known configuration (the jwks
  // itself is fetched and cached separately) and only fail if there never was one
  const resolveStaleConfiguration = (error: unknown): OidcConfiguration => {
    if (cache) {
      return cache.configuration;
    }

    throw error;
  };

  const resolveConfiguration = async (): Promise<OidcConfiguration> => {
    try {
      const configuration = await fetchConfiguration();

      cache = { configuration, validUntil: Date.now() + maxAge * 1000 };
      failure = undefined;

      return configuration;
    } catch (error) {
      // fail fast during an outage instead of hitting the issuer with every request
      failure = { error, retryAfter: Date.now() + cooldown * 1000 };

      return resolveStaleConfiguration(error);
    } finally {
      pending = undefined;
    }
  };

  return async (): Promise<OidcConfiguration> => {
    if (cache && cache.validUntil > Date.now()) {
      return cache.configuration;
    }

    if (failure && failure.retryAfter > Date.now()) {
      return resolveStaleConfiguration(failure.error);
    }

    // concurrent cache misses share one in-flight request
    pending ??= resolveConfiguration();

    return pending;
  };
};
