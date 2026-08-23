import type { Container } from '@chubbyts/chubbyts-dic-types/dist/container';
import { createAbstractFactory } from '@chubbyts/chubbyts-dic-config-factory/dist/dic-config-factory';
import type { Logger } from '@chubbyts/chubbyts-log-types/dist/log';
import type { Middleware } from '@chubbyts/chubbyts-undici-server/dist/server';
import type { OidcConfigurationResolver, OidcConfigurationResolverOptions } from './discovery.js';
import { createOidcConfigurationResolver } from './discovery.js';
import { createOidcAuthenticationMiddleware } from './middleware.js';
import type { JwtTokenVerifierOptions, TokenExtractor, TokenVerifier } from './token.js';
import { createBearerTokenExtractor, createJwtTokenVerifier } from './token.js';

/**
 * The configuration read by the service factories from `config.chubbyts.oidc` (or `config.chubbyts.oidc.<name>` for
 * named factories), see the options of `createOidcConfigurationResolver`, `createJwtTokenVerifier` and
 * `createOidcAuthenticationMiddleware`.
 */
export type OidcConfig = {
  issuer: string;
  realm?: string;
} & OidcConfigurationResolverOptions &
  JwtTokenVerifierOptions;

type Config = {
  chubbyts: {
    oidc: OidcConfig | Record<string, OidcConfig>;
  };
};

export const bearerTokenExtractorServiceFactory = createAbstractFactory((): TokenExtractor => {
  return createBearerTokenExtractor();
});

export const oidcConfigurationResolverServiceFactory = createAbstractFactory(
  (container: Container, { resolveConfig }): OidcConfigurationResolver => {
    const oidcConfig = resolveConfig(container.get<Config>('config').chubbyts.oidc);

    return createOidcConfigurationResolver(oidcConfig.issuer, oidcConfig);
  },
);

export const jwtTokenVerifierServiceFactory = createAbstractFactory(
  (container: Container, { resolveConfig, resolveDependency }): TokenVerifier => {
    const oidcConfig = resolveConfig(container.get<Config>('config').chubbyts.oidc);

    // a registered service wins over the shipped factory, so that any part can be replaced or shared between services
    const oidcConfigurationResolver = resolveDependency(
      container,
      'oidcConfigurationResolver',
      oidcConfigurationResolverServiceFactory,
    );

    return createJwtTokenVerifier(oidcConfigurationResolver, oidcConfig);
  },
);

export const oidcAuthenticationMiddlewareServiceFactory = createAbstractFactory(
  (container: Container, { resolveConfig, resolveDependency }): Middleware => {
    const { realm } = resolveConfig(container.get<Config>('config').chubbyts.oidc);

    return createOidcAuthenticationMiddleware(
      resolveDependency(container, 'oidcTokenExtractor', bearerTokenExtractorServiceFactory),
      resolveDependency(container, 'oidcTokenVerifier', jwtTokenVerifierServiceFactory),
      realm,
      container.has('logger') ? container.get<Logger>('logger') : undefined,
    );
  },
);
