const crypto = require('crypto')
const Promise = require('bluebird')

// TODO: Can we mock this require in testing?
const api = require('./api')

function encrypt (context, data) {
  return api.newKey(context)
    .then((response) => {
      /*
       * Prepare, generate a unique IV and get a new key to use
       */
      const iv = crypto.randomBytes(16)
      const tmpKey = response

      const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(tmpKey.key, 'base64'), iv)

      /*
       * We pass the kid as AAD here, note that it's NOT part of the resulting encrypted string - just part of hash
       */
      cipher.setAAD(Buffer.from(tmpKey.kid, 'base64'))

      /*
       * Add the actual data from buf and complete the encryption
       */
      let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'base64')
      encrypted += cipher.final('base64')

      /*
       * As stated above, there is no standard way to concat. The following seems
       * to be "default": IV + ciphertext + authtag
       * In our case we want to pass the AAD as well in plaintext:
       * IV + ciphertext + aad + authtag
       */
      return iv.toString('base64') + ':' + encrypted + ':' + tmpKey.kid + ':' + cipher.getAuthTag().toString('base64')
    })
    .catch((e) => {
      throw new Error('Request to keyruler server failed')
    })
}

function decrypt (encrypted) {
  if (encrypted === undefined || encrypted === null) {
    return Promise.reject(new Error('Encrypted string not valid'))
  }
  /*
   * TODO error handling, invalid count etc
   */
  const parts = encrypted.split(':')

  if (parts.length !== 4) {
    return Promise.reject(new Error('Encrypted string not valid'))
  }

  // 0: IV, 1: Encrypted data, 2: Key id, 3: Auth tag
  return api.getKey(parts[2])
    .then((response) => {
      let iv = Buffer.from(parts[0], 'base64')
      let tmpKey = response.key

      let decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(tmpKey, 'base64'), iv)

      /*
       * Set the AAD and authtag
       */
      decipher.setAAD(Buffer.from(parts[2], 'base64'))
      decipher.setAuthTag(Buffer.from(parts[3], 'base64'))

      /*
       * Actual decryption back to utf8 string
       */
      let decrypted = decipher.update(parts[1], 'base64', 'utf8')
      decrypted += decipher.final('utf8')

      return JSON.parse(decrypted)
    })
    .catch((e) => {
      throw new Error('Request to keyruler server failed')
    })
}

function doHMAC (data) {
  return api.newKey('hmac')
    .then((response) => {
      let hmac = crypto.createHmac('sha256', response.key)
      hmac.update(data)
      return hmac.digest('hex')
    })
    .catch((e) => {
      return new Error('Request to keyruler server failed')
    })
}

module.exports = {
  encrypt,
  decrypt,
  doHMAC
}
