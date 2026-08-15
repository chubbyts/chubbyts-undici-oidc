/**
 * Thrown by a token verifier if the given token itself is invalid (malformed, wrong signature, expired, wrong
 * issuer / audience, ...). Any other error thrown by a token verifier is treated as an internal failure
 * (unreachable discovery / jwks endpoint, ...) and gets rethrown by the middleware.
 */
export class InvalidTokenError extends Error {
  public constructor(message: string, cause?: unknown) {
    super(message, { cause });
    // oxlint-disable-next-line functional/immutable-data
    this.name = 'InvalidTokenError';
  }
}
