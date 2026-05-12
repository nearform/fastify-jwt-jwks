'use strict'

const { Unauthorized, InternalServerError } = require('http-errors')

const errorMessages = require('./error-messages')

function getHeader(requestOrToken, verifyFunctionName, decodeFunctionName) {
  const isRequest = typeof requestOrToken[verifyFunctionName] === 'function'

  if (isRequest) {
    return requestOrToken[decodeFunctionName]({ decode: { complete: true } })
      .then(decoded => decoded.header)
      .catch(() => {
        throw new Unauthorized(errorMessages.invalidToken)
      })
  } else {
    const isDecodedToken = !!requestOrToken.header
    if (isDecodedToken) {
      return Promise.resolve(requestOrToken.header)
    } else {
      return Promise.reject(new InternalServerError(errorMessages.unexpectedContext))
    }
  }
}

module.exports = getHeader
