'use strict'

const { Unauthorized, InternalServerError } = require('http-errors')
const fastifyPlugin = require('fastify-plugin')
const fastifyJwt = require('@fastify/jwt')
const fetch = require('node-fetch')
const NodeCache = require('node-cache')
const { createPublicKey } = require('node:crypto')

const forbiddenOptions = ['algorithms']

const errorMessages = {
  badHeaderFormat: 'Authorization header should be in format: Bearer [token].',
  expiredToken: 'Expired token.',
  invalidAlgorithm: 'Unsupported token.',
  invalidToken: 'Invalid token.',
  jwksHttpError: 'Unable to get the JWS due to a HTTP error',
  missingHeader: 'Missing Authorization HTTP header.',
  missingKey: 'Missing Key: Public key must be provided',
  missingOptions: 'Please provide at least one of the "jwksUrl" or "secret" options.'
}

const fastifyJwtErrors = [
  ['Format is Authorization: Bearer \\[token\\]', errorMessages.badHeaderFormat],
  ['No Authorization was found in request\\.headers', errorMessages.missingHeader],
  ['token expired', errorMessages.expiredToken],
  ['invalid algorithm', errorMessages.invalidAlgorithm],
  [/(?:jwt malformed)|(?:invalid signature)|(?:jwt (?:audience|issuer) invalid)/, errorMessages.invalidToken]
]

function verifyOptions(options) {
  let { jwksUrl, audience, secret, issuer } = options

  // Do not allow some options to be overidden by original user provided
  for (const key of forbiddenOptions) {
    if (key in options) {
      throw new Error(`Option "${key}" is not supported.`)
    }
  }

  // Prepare verification options
  const verify = Object.assign({}, options, { algorithms: [] })

  let jwksUrlObject
  let jwksUrlOrigin

  if (jwksUrl) {
    jwksUrl = jwksUrl.toString()

    // Normalize to get a complete URL for JWKS fetching
    if (!jwksUrl.match(/^http(?:s?)/)) {
      jwksUrlObject = new URL(`https://${jwksUrl}`)
      jwksUrl = jwksUrlObject.toString()
    } else {
      // adds missing trailing slash if it's not been provided in the config
      jwksUrlObject = new URL(jwksUrl)
      jwksUrl = jwksUrlObject.toString()
    }

    jwksUrlOrigin = jwksUrlObject.origin + '/'

    verify.algorithms.push('RS256')
    // @TODO normalize issuer url like done for jwksUrl
    verify.allowedIss = issuer || jwksUrlOrigin

    if (audience) {
      verify.allowedAud = jwksUrlOrigin
    }
  }

  if (audience) {
    verify.allowedAud = audience === true ? jwksUrlOrigin : audience
  }

  if (secret) {
    secret = secret.toString()
    verify.algorithms.push('HS256')
  }

  if (!jwksUrl && !secret) {
    // If there is no jwksUrl and no secret no verifications are possible, throw an error
    throw new Error(errorMessages.missingOptions)
  }

  return { jwksUrl, audience, secret, verify }
}

async function getRemoteSecret(jwksUrl, alg, kid, cache) {
  try {
    const cacheKey = `${alg}:${kid}:${jwksUrl}`

    const cached = cache.get(cacheKey)

    if (cached) {
      return cached
    } else if (cached === null) {
      // null is returned when a previous attempt resulted in the key missing in the JWKs - Do not attempt to fetch again
      throw new Unauthorized(errorMessages.missingKey)
    }

    // Hit the well-known URL in order to get the key
    const response = await fetch(jwksUrl, { timeout: 5000 })

    const body = await response.json()

    if (!response.ok) {
      const error = new Error(response.statusText)
      error.response = response
      error.body = body

      throw error
    }

    // Find the key with ID and algorithm matching the JWT token header
    const key = body.keys.find(
      k => k.kid === kid && ((k.alg && k.alg === alg) || (k.kty && k.kty === 'RSA' && k.use === 'sig'))
    )

    if (!key) {
      // Mark the key as missing
      cache.set(cacheKey, null)
      throw new Unauthorized(errorMessages.missingKey)
    }

    let secret
    if (key.x5c) {
      // @TODO This comes from a previous implementation: check whether this condition is still necessary
      // certToPEM extracted from https://github.com/auth0/node-jwks-rsa/blob/master/src/utils.js
      secret = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----\n`
    } else {
      const publicKey = await createPublicKey({ key, format: 'jwk' })
      secret = publicKey.export({ type: 'spki', format: 'pem' })
    }

    // Save the key in the cache
    cache.set(cacheKey, secret)
    return secret
  } catch (e) {
    if (e.response) {
      throw InternalServerError(`${errorMessages.jwksHttpError}: [HTTP ${e.response.status}] ${JSON.stringify(e.body)}`)
    }

    e.statusCode = e.statusCode || 500
    throw e
  }
}

function fastifyJwtJwks(instance, options, done) {
  try {
    // Construct the JWT function names and this plugin's decorator names using the same rules as @fastify/jwt
    const { namespace } = options
    const decodeFunctionName = namespace ? `${namespace}JwtDecode` : 'jwtDecode'
    const verifyFunctionName = namespace ? `${namespace}JwtVerify` : 'jwtVerify'
    const authenticateMethodName = namespace ? `${namespace}Authenticate` : 'authenticate'
    const jwksOptionsName = namespace ? `${namespace}JwtJwks` : 'jwtJwks'
    const secretsCacheName = namespace ? `${namespace}JwtJwksSecretsCache` : 'jwtJwksSecretsCache'

    function getSecret(request, reply, cb) {
      request[decodeFunctionName]({ decode: { complete: true } })
        .then(decoded => {
          const { header } = decoded
          // If the algorithm is not using RS256, the encryption key is jwt client secret
          if (header.alg.startsWith('HS')) {
            if (!request[jwksOptionsName].secret) {
              throw new Unauthorized(errorMessages.invalidAlgorithm)
            }
            return cb(null, request[jwksOptionsName].secret)
          }

          // If the algorithm is RS256, get the key remotely using a well-known URL containing a JWK set
          getRemoteSecret(request[jwksOptionsName].jwksUrl, header.alg, header.kid, request[secretsCacheName])
            .then(key => cb(null, key))
            .catch(cb)
        })
        .catch(cb)
    }

    async function authenticate(request, reply) {
      try {
        await request[verifyFunctionName]()
      } catch (e) {
        for (const [jwtMessage, errorMessage] of fastifyJwtErrors) {
          if (e.message.match(jwtMessage)) {
            throw new Unauthorized(errorMessage, { a: 1 })
          }
        }

        if (e.statusCode) {
          throw e
        }

        throw new Unauthorized(e.message)
      }
    }

    // Check if secrets cache is wanted - Convert milliseconds to seconds and cache for a week by default
    const ttl = parseFloat('secretsTtl' in options ? options.secretsTtl : '604800000', 10) / 1e3
    delete options.secretsTtl

    const jwtJwksOptions = verifyOptions(options)

    // Setup @fastify/jwt
    instance.register(fastifyJwt, {
      verify: jwtJwksOptions.verify,
      cookie: options.cookie,
      secret: getSecret,
      formatUser: options.formatUser,
      namespace
    })

    // Setup our decorators
    instance.decorate(authenticateMethodName, authenticate)
    instance.decorate(jwksOptionsName, jwtJwksOptions)
    instance.decorateRequest(jwksOptionsName, {
      getter: () => jwtJwksOptions
    })

    const cache =
      ttl > 0 ? new NodeCache({ stdTTL: ttl }) : { get: () => undefined, set: () => false, close: () => undefined }

    // Create a cache or a fake cache
    instance.decorateRequest(secretsCacheName, {
      getter: () => cache
    })

    instance.addHook('onClose', () => cache.close())

    done()
  } catch (e) {
    done(e)
  }
}

module.exports = fastifyPlugin(fastifyJwtJwks, { name: 'fastify-jwt-jwks', fastify: '>=4.0.0' })
module.exports.default = fastifyJwtJwks
module.exports.fastifyJwtJwks = fastifyJwtJwks
