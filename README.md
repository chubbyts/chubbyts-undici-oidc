# chubbyts-undici-oidc

[![CI](https://github.com/chubbyts/chubbyts-undici-oidc/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/chubbyts/chubbyts-undici-oidc/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/chubbyts/chubbyts-undici-oidc/badge.svg?branch=master)](https://coveralls.io/github/chubbyts/chubbyts-undici-oidc?branch=master)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fchubbyts%2Fchubbyts-undici-oidc%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/chubbyts/chubbyts-undici-oidc/master)
[![npm-version](https://img.shields.io/npm/v/@chubbyts/chubbyts-undici-oidc.svg)](https://www.npmjs.com/package/@chubbyts/chubbyts-undici-oidc)

[![bugs](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=bugs)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![code_smells](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=code_smells)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![coverage](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=coverage)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![duplicated_lines_density](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![ncloc](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=ncloc)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![sqale_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![alert_status](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=alert_status)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![reliability_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![security_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=security_rating)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![sqale_index](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=sqale_index)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)
[![vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=chubbyts_chubbyts-undici-oidc&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=chubbyts_chubbyts-undici-oidc)

## Description

A minimal OIDC (OpenID Connect) resource server integration for chubbyts-undici-server. It resolves the openid configuration of the given issuer, verifies JWT based bearer tokens against the issuer's JWKS and passes the verified claims to the handler via request attributes.

## Requirements

 * node: 22
 * [@chubbyts/chubbyts-log-types][2]: ^3.3.0
 * [@chubbyts/chubbyts-undici-server][3]: ^1.2.0
 * [jose][4]: ^6.2.8

## Installation

Through [NPM](https://www.npmjs.com) as [@chubbyts/chubbyts-undici-oidc][1].

```sh
npm i @chubbyts/chubbyts-undici-oidc@^1.0.0-beta.1
```

## Usage

```ts
import type { OidcAttributes } from '@chubbyts/chubbyts-undici-oidc/dist/middleware';
import { createOidcConfigurationResolver } from '@chubbyts/chubbyts-undici-oidc/dist/discovery';
import { createOidcAuthenticationMiddleware } from '@chubbyts/chubbyts-undici-oidc/dist/middleware';
import { createBearerTokenExtractor, createJwtTokenVerifier } from '@chubbyts/chubbyts-undici-oidc/dist/token';
import type { Handler, ServerRequest } from '@chubbyts/chubbyts-undici-server/dist/server';
import { Response } from '@chubbyts/chubbyts-undici-server/dist/server';

const oidcAuthenticationMiddleware = createOidcAuthenticationMiddleware(
  createBearerTokenExtractor(),
  createJwtTokenVerifier(createOidcConfigurationResolver('https://issuer.example.com'), {
    audience: 'https://api.example.com',
  }),
  'api',
);

// register the middleware for the routes (or route group) you want to protect, public routes simply don't get it,
// e.g. within chubbyts-framework: createGroup({ path: '/api', ..., middlewares: [oidcAuthenticationMiddleware, ...] })

const handler: Handler = async (serverRequest: ServerRequest<OidcAttributes>): Promise<Response> => {
  const { oidc } = serverRequest.attributes; // { token: string, claims: JWTPayload } | undefined

  return new Response(JSON.stringify({ sub: oidc?.claims.sub }), { headers: { 'content-type': 'application/json' } });
};
```

If the request does not contain a valid bearer token, the middleware returns a `401` response with a `WWW-Authenticate` challenge and the handler does not get called:

 * missing token: `WWW-Authenticate: Bearer realm="api"`
 * invalid token: `WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token is invalid or expired"`

The challenge allows a client to distinguish a missing from an invalid token, but never contains the actual verification error (expired, wrong signature, ... it may also leak internal details like the issuer or jwks uri); the reason gets logged with level `info` via the optional logger instead. Errors which are not related to the token itself (unreachable discovery / jwks endpoint, ...) get rethrown, so your error handling (e.g. an error middleware) can log them and respond with a `5xx` status. On success the handler receives a request with the `oidc` attribute: `{ token: string, claims: JWTPayload }` (see the exported `OidcAttributes` type).

**Warning:** Always pass the `audience` option and make sure it matches the audience (`aud` claim) your authorization server assigns to access tokens meant for your API. Without it, any valid token of the issuer gets accepted, even ones issued for other APIs.

**Browser based clients:** Allow the `Authorization` request header within your cors configuration (e.g. `allowHeaders`) and expose the `WWW-Authenticate` response header (e.g. `exposeHeaders`), if the frontend should be able to read the challenge.

### discovery

#### createOidcConfigurationResolver

Resolves the openid configuration from `{issuer}/.well-known/openid-configuration`, validates the issuer and caches the result (`maxAge`, default: 3600 seconds).

```ts
import { createOidcConfigurationResolver } from '@chubbyts/chubbyts-undici-oidc/dist/discovery';

const oidcConfigurationResolver = createOidcConfigurationResolver('https://issuer.example.com', fetch, 3600);
```

Things to be aware of:

 * **Lazy:** The configuration gets resolved on first use (first token verification), not on creation. Your application boots even if the issuer is not reachable yet, but requests during that time fail with the rethrown error (see the middleware). A failed resolution does not get cached, the next request retries.
 * **Issuer:** Pass the issuer exactly as the provider reports it within its configuration (`iss` claim), the comparison is strict, e.g. `https://issuer.example.com` and `https://issuer.example.com/` are not the same.
 * **fetch:** The optional `fetch` argument allows a custom implementation (e.g. undici with a custom dispatcher / proxy or a mock in tests). It is only used for the discovery request, the jwks requests use the `fetch` option of `createJwtTokenVerifier`.

### token

#### createBearerTokenExtractor

Extracts the bearer token from the `Authorization` request header.

```ts
import { createBearerTokenExtractor } from '@chubbyts/chubbyts-undici-oidc/dist/token';

const tokenExtractor = createBearerTokenExtractor();
```

#### createJwtTokenVerifier

Verifies a JWT based token (signature via the issuer's JWKS, `iss`, `exp`, `nbf` and optionally `aud` and allowed algorithms) and returns its claims. Throws an `InvalidTokenError` (see `error`) if the token itself is invalid, any other error (e.g. discovery or jwks fetch failure) gets passed through.

```ts
import { createOidcConfigurationResolver } from '@chubbyts/chubbyts-undici-oidc/dist/discovery';
import { createJwtTokenVerifier } from '@chubbyts/chubbyts-undici-oidc/dist/token';

const tokenVerifier = createJwtTokenVerifier(createOidcConfigurationResolver('https://issuer.example.com'), {
  audience: 'https://api.example.com', // string | Array<string>, see the warning above
  algorithms: ['RS256'], // default: any asymmetric algorithm supported by jose
  clockTolerance: 5, // seconds, default: 0
  fetch, // custom fetch for the jwks requests, default: globalThis.fetch
});
```

The JWKS gets fetched via [jose][4]'s `createRemoteJWKSet` and is cached in memory, unknown key ids (e.g. after a key rotation) trigger a refetch (rate limited by jose). If the `jwks_uri` within the openid configuration changes, a new JWKS resolver gets created.

### middleware

#### createOidcAuthenticationMiddleware

```ts
import { createOidcAuthenticationMiddleware } from '@chubbyts/chubbyts-undici-oidc/dist/middleware';

const oidcAuthenticationMiddleware = createOidcAuthenticationMiddleware(
  tokenExtractor,
  tokenVerifier,
  'api', // realm, optional
  logger, // optional
);
```

 * `realm`: Optional, gets added to the `WWW-Authenticate` challenge as `realm="api"`, nothing else depends on it.
 * `logger`: Optional [@chubbyts/chubbyts-log-types][2] compatible logger (e.g. [@chubbyts/chubbyts-pino-adapter][8]), defaults to a no-op logger. Pass a real one to see *why* tokens got rejected (level `info`, including method and path), because this information intentionally does not get reflected to the client.

### error

#### InvalidTokenError

Thrown by the token verifier if the token itself is invalid (malformed, wrong signature, expired, wrong issuer / audience, ...). Custom `TokenVerifier` implementations need to throw it to get the `401` response, any other error gets rethrown by the middleware.

```ts
import { InvalidTokenError } from '@chubbyts/chubbyts-undici-oidc/dist/error';

throw new InvalidTokenError('token expired', cause);
```

## Testing against a local OIDC provider

The easiest way to test the integration manually is [Keycloak][5] as a docker container:

```sh
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7 start-dev
```

Within the admin console at http://localhost:8080 (admin/admin):

 1. Create a realm `test`.
 2. Create a client `api` with *Client authentication* and the *Service accounts roles* flow enabled.

For a reproducible setup (e.g. within docker compose) export the realm afterwards and let keycloak import it on startup: `start-dev --import-realm` with the exported json mounted at `/opt/keycloak/data/import`, see [chubbyts-petstore][9] for a complete example.

```sh
# the openid configuration resolved by createOidcConfigurationResolver
curl http://localhost:8080/realms/test/.well-known/openid-configuration

# get a real access token
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=api -d client_secret=<client-secret>
```

```ts
const oidcConfigurationResolver = createOidcConfigurationResolver('http://localhost:8080/realms/test');
```

Things to be aware of:

 * **Audience:** Keycloak access tokens contain `aud: "account"` by default. With the `audience` option set, verification fails with `unexpected "aud" claim value` until you add an *audience mapper* to the client scope.
 * **Issuer:** By default the `iss` claim matches the URL the token was requested through. Use the same host for the resolver and the token request (do not mix `localhost` and `127.0.0.1`), otherwise the issuer validation fails. As soon as tokens get requested from different hosts (e.g. docker compose: the api resolves the configuration via `http://keycloak:8080`, tokens get requested from the host via `http://localhost:8080`), fix the hostname instead: `KC_HOSTNAME=http://keycloak:8080` makes the issuer always `http://keycloak:8080/realms/test` (requests via other hostnames get redirected) and an entry `127.0.0.1 keycloak` in `/etc/hosts` makes it reachable from the host as well.

For automated integration tests (e.g. within CI) [mock-oauth2-server][6] (`ghcr.io/navikt/mock-oauth2-server`) is a lightweight alternative which issues tokens for any client without any setup. This repository ships such an integration test suite:

```sh
pnpm test:integration --run
```

It starts the mock-oauth2-server container via [testcontainers][7] on a random port (and stops it afterwards), fetches real tokens through the `client_credentials` grant and runs them through the whole middleware stack. A docker compatible daemon (docker, podman, colima, ...) needs to be running. If a server is already running (or reachable elsewhere), it gets reused instead: set `MOCK_OAUTH2_SERVER_URL` (default: `http://localhost:8080`) to point at it.

## Copyright

2026 Dominik Zogg

[1]: https://www.npmjs.com/package/@chubbyts/chubbyts-undici-oidc
[2]: https://www.npmjs.com/package/@chubbyts/chubbyts-log-types
[3]: https://www.npmjs.com/package/@chubbyts/chubbyts-undici-server
[4]: https://www.npmjs.com/package/jose
[5]: https://www.keycloak.org
[6]: https://github.com/navikt/mock-oauth2-server
[7]: https://www.npmjs.com/package/testcontainers
[8]: https://www.npmjs.com/package/@chubbyts/chubbyts-pino-adapter
[9]: https://github.com/chubbyts/chubbyts-petstore
