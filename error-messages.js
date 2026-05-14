'use strict'

module.exports = {
  badHeaderFormat: 'Authorization header should be in format: Bearer [token].',
  expiredToken: 'Expired token.',
  invalidAlgorithm: 'Unsupported token.',
  invalidToken: 'Invalid token.',
  jwksHttpError: 'Unable to get the JWS due to a HTTP error',
  missingHeader: 'Missing Authorization HTTP header.',
  missingKey: 'Missing Key: Public key must be provided',
  missingOptions: 'Please provide at least one of the "jwksUrl" or "secret" options.',
  unexpectedContext: 'Unexpected context: getSecret called outside known fastify contexts.'
}
