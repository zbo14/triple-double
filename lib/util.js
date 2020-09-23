'use strict'

const crypto = require('crypto')
const nacl = require('tweetnacl')
const uuid = require('uuid')

const encrypt = ({ iv, key, plaintext }) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)

  return Buffer.concat([
    cipher.update(Buffer.from(plaintext)),
    cipher.final()
  ])
}

const decrypt = ({ ciphertext, iv, key }) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)

  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ])
}

const genKeyPair = () => {
  let { publicKey: pubKey, secretKey: privKey } = nacl.box.keyPair()

  pubKey = Buffer.from(pubKey)
  privKey = Buffer.from(privKey)

  return { pubKey, privKey }
}

const hmac = ({ data, key }) => {
  const hmac = crypto.createHmac('sha256', key)

  hmac.update(data)

  return hmac.digest()
}

const hkdf = ({ ikm, info, length, salt }) => {
  salt = salt || Buffer.alloc(32)
  const key = hmac({ data: ikm, key: salt })

  let t = Buffer.alloc(0)
  let okm = Buffer.alloc(0)

  for (let i = 0; i < Math.ceil(length / 32); i++) {
    const data = Buffer.concat([t, info, Buffer.from([1 + i])])
    t = hmac({ data, key })
    okm = Buffer.concat([okm, t])
  }

  return okm.slice(0, length)
}

const isArray = x => Array.isArray(x)
const isBuffer = x => Buffer.isBuffer(x)
const isInteger = x => Number.isInteger(x)
const isIntegerInRange = (a, b) => x => isInteger(x) && x >= a && x <= b
const isString = x => typeof x === 'string'
const isNonEmptyString = x => x && isString(x)
const isUUID = x => uuid.validate(x)
const isArrayPublicKeys = x => isArray(x) && x.every(isPublicKey)
const isBufferOrString = x => isBuffer(x) || isString(x)

const isPublicKey = x => {
  try {
    if (typeof x === 'string') {
      x = Buffer.from(x, 'base64')
    } else {
      x = Buffer.from(x)
    }
  } catch {
    return false
  }

  return x.byteLength === nacl.box.publicKeyLength
}

const isSignature = x => {
  try {
    if (typeof x === 'string') {
      x = Buffer.from(x, 'base64')
    } else {
      x = Buffer.from(x)
    }
  } catch {
    return false
  }

  return x.byteLength === nacl.sign.signatureLength
}

const validators = {
  'an array': isArray,
  'a buffer': isBuffer,
  'a buffer or string': isBufferOrString,
  'an integer': isInteger,
  'a string': isString,
  'a non-empty string': isNonEmptyString,
  'a public key': isPublicKey,
  'a signature': isSignature,
  'a UUID': isUUID,
  'an array of public keys': isArrayPublicKeys,
  'a valid port number': isIntegerInRange(1, 65535)
}

const validate = (...args) => {
  for (const [key, type, value] of args) {
    if (!validators[type](value)) {
      throw new Error(`Expected ${key} to be ${type}`)
    }
  }
}

module.exports = {
  decrypt,
  encrypt,
  genKeyPair,
  hkdf,
  hmac,
  validate
}
