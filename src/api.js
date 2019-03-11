const request = require('request-promise')

// TODO: Depend on environment variable
const KEYRULER_INSTANCE_HOST = 'http://localhost:3004'

function newKey (context) {
  const contextParam = encodeURIComponent(context)
  return request.post(`${KEYRULER_INSTANCE_HOST}/newKey?context=${contextParam}`, { json: true })
}

function getKey (keyId) {
  return request.get(`${KEYRULER_INSTANCE_HOST}/getKey`, { qs: { kid: keyId }, json: true })
}

module.exports = {
  getKey,
  newKey
}
