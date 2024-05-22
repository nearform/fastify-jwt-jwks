import { FastifyPluginCallback, FastifyReply, FastifyRequest } from 'fastify'
import { UserType, SignPayloadType } from '@fastify/jwt'

import NodeCache from 'node-cache'

export interface FastifyJwtJwksOptions {
  /**
   * JSON Web Key Set url (JWKS).
   * The public endpoint returning the set of keys that contain amongst other things the keys needed to verify JSON Web Tokens (JWT)
   * Eg. https://domain.com/.well-known/jwks.json
   */
  readonly jwksUrl?: string
  /**
   * The intended consumer of the token.
   * This is typically a set of endpoints at which the token can be used.
   * If you provide the value `true`, the domain will be also used as audience.
   * Accepts a string value, or an array of strings for multiple audiences.
   */
  readonly audience?: string | readonly string[] | boolean
  /**
   * The domain of the system which is issuing OAuth access tokens.
   * By default the domain will be also used as audience.
   * Accepts a string value, or an array of strings for multiple issuers.
   */
  readonly issuer?: string | RegExp | (RegExp | string)[]
  /**
   * The OAuth client secret. It enables verification of HS256 encoded JWT tokens.
   */
  readonly secret?: string
  /**
   * If to return also the header and signature of the verified token.
   */
  readonly complete?: boolean
  /**
   * How long (in milliseconds) to cache RS256 secrets before getting them
   * again using well known JWKS URLS. Setting to 0 or less disables the cache.
   */
  readonly secretsTtl?: string | number

  /**
   * Used to indicate that the token can be passed using cookie, instead of the Authorization header.
   */
  readonly cookie?: {
    /**
     *  The name of the cookie.
     */
    cookieName: string

    /**
     *  Indicates whether the cookie is signed or not. If set to `true`, the JWT
     *  will be verified using the unsigned value.
     */
    signed?: boolean
  }
  /**
   * You may customize the request.user object setting a custom sync function as parameter:
   */
  readonly formatUser?: (payload: SignPayloadType) => UserType
  /**
   * A string used to namespace the decorators of this plugin. This is to allow this plugin to be applied multiple times
   * to a single Fastify instance. See the description of the namespace parameter in @fastify/jwt.
   */
  readonly namespace?: string
}

export interface JwtJwks extends Pick<FastifyJwtJwksOptions, 'jwksUrl' | 'audience' | 'secret'> {
  readonly verify: FastifyJwtJwksOptions & {
    readonly algorithms: readonly string[]
    readonly audience?: string | readonly string[]
  }
}

export type Authenticate = (request: FastifyRequest, reply: FastifyReply) => Promise<void>

/**
 * JWT JWKS verification plugin for Fastify, internally uses @fastify/jwt and jsonwebtoken.
 */
export const fastifyJwtJwks: FastifyPluginCallback<FastifyJwtJwksOptions>
export default fastifyJwtJwks

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: Authenticate
    jwtJwks: JwtJwks
  }

  interface FastifyRequest {
    jwtJwks: JwtJwks
    jwtJwksSecretsCache: Pick<NodeCache, 'get' | 'set' | 'close'>
  }
}
