'use strict'

const { describe, test } = require('node:test')
const getHeader = require('../get-header')

describe('getHeader', function () {
  test('should extract the header from a request object', async function (t) {
    const request = {
      jwtVerify: function () {},
      jwtDecode: function () {
        return Promise.resolve({ header: { alg: 'RS256', kid: 'KEY' } })
      }
    }

    const header = await getHeader(request, 'jwtVerify', 'jwtDecode')

    t.assert.deepStrictEqual(header, { alg: 'RS256', kid: 'KEY' })
  })

  test('should throw Unauthorized when request decode fails', async function (t) {
    const request = {
      jwtVerify: function () {},
      jwtDecode: function () {
        return Promise.reject(new Error('decode error'))
      }
    }

    await t.assert.rejects(() => getHeader(request, 'jwtVerify', 'jwtDecode'), {
      message: 'Invalid token.',
      statusCode: 401
    })
  })

  test('should extract the header from a decoded token', async function (t) {
    const header = await getHeader({ header: { alg: 'RS256', kid: 'KEY' } }, 'jwtVerify', 'jwtDecode')

    t.assert.deepStrictEqual(header, { alg: 'RS256', kid: 'KEY' })
  })

  test('should extract the header from a decoded token with HS256', async function (t) {
    const header = await getHeader({ header: { alg: 'HS256', typ: 'JWT' } }, 'jwtVerify', 'jwtDecode')

    t.assert.deepStrictEqual(header, { alg: 'HS256', typ: 'JWT' })
  })

  test('should reject with InternalServerError for unexpected context', async function (t) {
    await t.assert.rejects(() => getHeader({}, 'jwtVerify', 'jwtDecode'), {
      message: 'Unexpected context: getSecret called outside known fastify contexts.',
      statusCode: 500
    })
  })

  test('should reject with InternalServerError for null input', async function (t) {
    await t.assert.rejects(() => getHeader({ header: null }, 'jwtVerify', 'jwtDecode'), {
      message: 'Unexpected context: getSecret called outside known fastify contexts.',
      statusCode: 500
    })
  })

  test('should use custom namespace function names', async function (t) {
    const request = {
      customJwtVerify: function () {},
      customJwtDecode: function () {
        return Promise.resolve({ header: { alg: 'RS256', kid: 'NS-KEY' } })
      }
    }

    const header = await getHeader(request, 'customJwtVerify', 'customJwtDecode')

    t.assert.deepStrictEqual(header, { alg: 'RS256', kid: 'NS-KEY' })
  })
})
