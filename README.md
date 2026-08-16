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

A minimal OIDC (OpenID Connect) resource server integration for chubbyts-undici-server: resolves the issuer's [openid configuration][10], verifies JWT bearer tokens against its [JWKS][11] and passes the verified claims to the handler via request attributes.

## Requirements

 * node: >=22
 * [@chubbyts/chubbyts-log-types][2]: ^3.3.0
 * [@chubbyts/chubbyts-undici-server][3]: ^1.2.0
 * [jose][4]: ^6.2.8

## Installation

Through [NPM](https://www.npmjs.com) as [@chubbyts/chubbyts-undici-oidc][1].

```sh
npm i @chubbyts/chubbyts-undici-oidc@^1.0.0-beta.4
```

## Usage

```ts
import { createOidcConfigurationResolver } from '@chubbyts/chubbyts-undici-oidc/dist/discovery';
import type { OidcAttributes } from '@chubbyts/chubbyts-undici-oidc/dist/middleware';
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

// add the middleware to the routes you want to protect, e.g. within chubbyts-framework:
// createGroup({ path: '/api', ..., middlewares: [oidcAuthenticationMiddleware, ...] })

const handler: Handler = async (serverRequest: ServerRequest<OidcAttributes>): Promise<Response> => {
  const { oidc } = serverRequest.attributes; // { token: string, claims: JWTPayload }

  return new Response(JSON.stringify({ sub: oidc.claims.sub }), { headers: { 'content-type': 'application/json' } });
};
```

 * **Audience:** `audience` is required and must match the `aud` claim your authorization server puts into access tokens for your API, otherwise any token of the issuer (even for other APIs, or ID tokens) would be accepted. If your server issues [RFC 9068][12] access tokens (`typ: at+jwt` header), pass `typ: 'at+jwt'` too.
 * **Rejected requests:** Without a valid token the handler is not called and a `401` with a [RFC 6750][13] challenge is returned: `WWW-Authenticate: Bearer realm="api"` (missing token) or `Bearer realm="api", error="invalid_token", error_description="The access token is invalid or expired"` (invalid token). The actual reason (expired, wrong signature, ...) is only logged (level `info`) via the optional logger, never sent to the client. Errors not related to the token (unreachable issuer, ...) are rethrown, so your error handling responds with a `5xx`.
 * **Browser clients:** Allow the `Authorization` request header and expose the `WWW-Authenticate` response header within your cors configuration.

### Options

```ts
import { createOidcConfigurationResolver } from '@chubbyts/chubbyts-undici-oidc/dist/discovery';
import { createOidcAuthenticationMiddleware } from '@chubbyts/chubbyts-undici-oidc/dist/middleware';
import { createBearerTokenExtractor, createJwtTokenVerifier } from '@chubbyts/chubbyts-undici-oidc/dist/token';

// resolves and caches {issuer}/.well-known/openid-configuration, lazily on first token verification
const oidcConfigurationResolver = createOidcConfigurationResolver('https://issuer.example.com', {
  fetch, // custom fetch for the discovery request, default: globalThis.fetch
  maxAge: 3600, // seconds a resolved configuration is cached, default: 3600
  timeout: 5, // seconds until the discovery request is aborted, default: 5
  cooldown: 30, // seconds until a failed (re)fetch is retried, default: 30
});

// verifies signature (via the issuer's JWKS), "iss", "aud", "exp", "nbf" and returns the claims
const tokenVerifier = createJwtTokenVerifier(oidcConfigurationResolver, {
  audience: 'https://api.example.com', // string | Array<string>, required (non-empty, enforced at runtime)
  algorithms: ['RS256'], // default: any asymmetric algorithm supported by jose
  clockTolerance: 5, // seconds, default: 0
  typ: 'at+jwt', // expected "typ" header, default: not checked
  requiredClaims: ['sub', 'iat', 'jti'], // additionally required claims, "iss", "aud" and "exp" always are
  fetch, // custom fetch for the jwks requests, default: globalThis.fetch
});

const oidcAuthenticationMiddleware = createOidcAuthenticationMiddleware(
  createBearerTokenExtractor(), // reads the "Authorization: Bearer <token>" header
  tokenVerifier,
  'api', // realm within the challenge, optional
  logger, // @chubbyts/chubbyts-log-types compatible logger, optional, default: no-op
);
```

 * **Issuer:** Must be exactly the `issuer` from the openid configuration (`iss` claim), `https://issuer.example.com` and `https://issuer.example.com/` are not the same. Use `https` in production, plain `http` is only meant for local development.
 * **Outages:** If the issuer is unreachable while the cached configuration is expired, the last known configuration keeps being served (and a refetch is retried after `cooldown`), so a temporary issuer outage does not take your api down. Only if there never was a successful resolution the error is thrown (`5xx`).
 * **JWKS:** Fetched and cached in memory by [jose][4]'s `createRemoteJWKSet`, unknown key ids (key rotation) trigger a rate limited refetch.
 * **Custom verifier:** A `TokenVerifier` is just `(token: string) => Promise<JWTPayload>`. Throw an `InvalidTokenError` (`@chubbyts/chubbyts-undici-oidc/dist/error`) to get the `401` response, any other error is rethrown.

## Testing against a local OIDC provider

[Keycloak][5] as a docker container is the easiest way to test manually:

```sh
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7 start-dev
```

Within the admin console at http://localhost:8080 (admin/admin) create a realm `test` and a client `api` with *Client authentication* and *Service accounts roles* enabled, then:

```sh
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=api -d client_secret=<client-secret>
```

```ts
const oidcConfigurationResolver = createOidcConfigurationResolver('http://localhost:8080/realms/test');
```

Keycloak specifics: access tokens contain `aud: "account"` until you add an *audience mapper*, have the header `typ: "JWT"` (not `at+jwt`) and the `iss` claim matches the URL the token was requested through, so use the same host for the resolver and the token request (or pin it, e.g. `KC_HOSTNAME=http://keycloak:8080` in docker compose). See [chubbyts-petstore][9] for a complete docker compose setup with an imported realm.

For automated tests [mock-oauth2-server][6] is a lightweight alternative which issues tokens without any setup. This repository's integration tests start it via [testcontainers][7] (docker compatible daemon required, set `MOCK_OAUTH2_SERVER_URL` to reuse a running one):

```sh
pnpm test:integration --run
```

## Copyright

2026 Dominik Zogg

[1]: https://www.npmjs.com/package/@chubbyts/chubbyts-undici-oidc
[2]: https://www.npmjs.com/package/@chubbyts/chubbyts-log-types
[3]: https://www.npmjs.com/package/@chubbyts/chubbyts-undici-server
[4]: https://www.npmjs.com/package/jose
[5]: https://www.keycloak.org
[6]: https://github.com/navikt/mock-oauth2-server
[7]: https://www.npmjs.com/package/testcontainers
[9]: https://github.com/chubbyts/chubbyts-petstore
[10]: https://openid.net/specs/openid-connect-discovery-1_0.html
[11]: https://www.rfc-editor.org/rfc/rfc7517
[12]: https://www.rfc-editor.org/rfc/rfc9068
[13]: https://www.rfc-editor.org/rfc/rfc6750
