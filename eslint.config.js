const js = require('@eslint/js')
const prettierRecommended = require('eslint-plugin-prettier/recommended')
const globals = require('globals')

module.exports = [
  js.configs.recommended,
  prettierRecommended,
  {
    languageOptions: {
      globals: {
        ...globals.node
      },
      ecmaVersion: 'latest',
      sourceType: 'commonjs'
    }
  }
]