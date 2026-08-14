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

const stripTrailingSlashes = (value: string): string => {
  return value.endsWith('/') ? stripTrailingSlashes(value.slice(0, -1)) : value;
};

export const createOidcConfigurationResolver = (
  issuer: string,
  fetch: typeof globalThis.fetch = globalThis.fetch,
  maxAge = 3600,
): OidcConfigurationResolver => {
  const url = `${stripTrailingSlashes(issuer)}/.well-known/openid-configuration`;

  // oxlint-disable-next-line functional/no-let
  let cache: { configuration: OidcConfiguration; validUntil: number } | undefined;

  return async (): Promise<OidcConfiguration> => {
    if (cache && cache.validUntil > Date.now()) {
      return cache.configuration;
    }

    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(`Cannot fetch oidc configuration from "${url}": status ${response.status}`);
    }

    const configuration = (await response.json()) as OidcConfiguration;

    if (configuration.issuer !== issuer) {
      throw new Error(`Issuer mismatch: expected "${issuer}", given "${configuration.issuer}"`);
    }

    // oxlint-disable-next-line functional/immutable-data
    cache = { configuration, validUntil: Date.now() + maxAge * 1000 };

    return configuration;
  };
};
