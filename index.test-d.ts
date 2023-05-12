import Fastify from 'fastify'
import fastifyJwtJwks from '.'
import { expectAssignable, expectType } from 'tsd'
import { DecodePayloadType, FastifyJwtDecodeOptions } from '@fastify/jwt'
import fastifyJWT from '@fastify/jwt'

const fastify = Fastify()

fastify.register(fastifyJwtJwks, {
  jwksUrl: '<JWKS url>',
  issuer: '<jwt issuer>',
  audience: '<jwt app audience>'
})
fastify.register(fastifyJwtJwks, {
  jwksUrl: '<JWKS url>',
  issuer: /<jwt issuer>/,
  audience: '<jwt app audience>'
})
fastify.register(fastifyJwtJwks, {
  jwksUrl: '<JWKS url>',
  issuer: ['<jwt issuer>', /<jwt issuer>/],
  audience: ['<jwt app audience>', '<jwt admin audience>']
})
fastify.register(fastifyJwtJwks, {
  jwksUrl: '<JWKS url>',
  audience: ['<jwt app audience>', '<jwt admin audience>']
})
fastify.register(fastifyJWT, {
  secret: '<jwt secret>'
})
fastify.register(fastifyJwtJwks, {
  cookie: {
    cookieName: '<cookie>',
    signed: true
  }
})
fastify.register(fastifyJwtJwks, {
  jwksUrl: '<JWKS url>',
  issuer: '<jwt issuer>',
  audience: '<jwt app audience>',
  formatUser: () => ({ foo: 'bar' })
})

fastify.register(function (instance, _options, done) {
  instance.get('/verify', {
    handler: function (request, reply) {
      expectAssignable<Function>(request.jwtDecode)

      const options: FastifyJwtDecodeOptions = {
        decode: {
          complete: true
        },
        verify: {}
      }

      expectType<Promise<DecodePayloadType>>(request.jwtDecode(options))
      expectType<Promise<DecodePayloadType>>(request.jwtDecode({ decode: { complete: true }, verify: {} }))
      expectType<Promise<DecodePayloadType>>(request.jwtDecode())

      reply.send(request.user)
    },
    preValidation: instance.authenticate
  })

  done()
})
