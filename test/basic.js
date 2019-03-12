const assert = require('assert')
const nock = require('nock')

const KEYRULER_HOST = 'http://localhost:3004'
const keyruler = require('../src/index')

describe('Basic tests', () => {
  before(() => {
    nock(KEYRULER_HOST)
      .post('/newKey')
      .query({ context: /\w+/gi })
      .reply(200, { kid: 'this_is_a_kid', key: 'a2V5X3dpdGhfcmVxdWlyZWRfbGVuZ3RoX29mXzMyX18=' })
      .get('/getKey')
      .query({ kid: 'this_is_a_kid' })
      .reply(200, { key: 'a2V5X3dpdGhfcmVxdWlyZWRfbGVuZ3RoX29mXzMyX18=' })
      .persist()
  })

  it('Encrypt -> Decrypt', async () => {
    const plain = 'THIS IS SOME PLAIN TEXT'
    const encrypted = await keyruler.encrypt(KEYRULER_HOST, 'test_context', plain)
    const decrypted = await keyruler.decrypt(KEYRULER_HOST, encrypted)

    assert.strictEqual(decrypted, plain)
  })

  it('Encrypted string not valid', async () => {
    const fakeEncrypted = 'iv_base64:encrypted_data:kid' // Missing auth tag
    assertThrowsAsync(() => keyruler.decrypt(KEYRULER_HOST, fakeEncrypted))
    assertThrowsAsync(() => keyruler.decrypt(KEYRULER_HOST, null))
    assertThrowsAsync(() => keyruler.decrypt(KEYRULER_HOST, undefined))
  })
})

function assertThrowsAsync (fn, regExp) {
  let f = () => { }
  try {
    return Promise.resolve(fn())
      .catch(e => {
        f = () => { throw e }
        return f
      })
      .then(() => assert.throws(f, regExp))
  } catch (e) {
    f = () => { throw e }
    assert.throws(f, regExp)
  }
}

// eslint-disable-next-line no-unused-vars
function assertDoesNotThrowsAsync (fn, regExp) {
  let f = () => { }
  try {
    return Promise.resolve(fn())
      .catch(e => {
        f = () => { throw e }
        return f
      })
      .then(() => assert.doesNotThrow(f, regExp))
  } catch (e) {
    f = () => { throw e }
    assert.doesNotThrow(f, regExp)
  }
}
