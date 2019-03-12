const request = require('request-promise')

function newKey (host, context) {
  const contextParam = encodeURIComponent(context)
  return request.post(`${host}/newKey?context=${contextParam}`, { json: true })
}

function getKey (host, keyId) {
  return request.get(`${host}/getKey`, { qs: { kid: keyId }, json: true })
}

module.exports = {
  getKey,
  newKey
}
