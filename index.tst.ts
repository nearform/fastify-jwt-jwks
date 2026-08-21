import Fastify from 'fastify'
import fastifyJwtJwks from '.'
import { expect } from 'tstyche'
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
fastify.register(fastifyJwtJwks, {
  secret: '<jwt secret>',
  decoratorName: '<custom decorator name>'
})

fastify.register(function (instance, _options, done) {
  instance.get('/verify', {
    handler: function (request, reply) {
      const options: FastifyJwtDecodeOptions = {
        decode: {
          complete: true
        },
        verify: {}
      }

      expect(request.jwtDecode(options)).type.toBe<Promise<DecodePayloadType>>()
      expect(request.jwtDecode({ decode: { complete: true }, verify: {} })).type.toBe<Promise<DecodePayloadType>>()
      expect(request.jwtDecode()).type.toBe<Promise<DecodePayloadType>>()

      reply.send(request.user)
    },
    preValidation: instance.authenticate
  })

  done()
})