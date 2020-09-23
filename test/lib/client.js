'use strict'

const assert = require('assert')
const { once } = require('events')
const sinon = require('sinon')
const Client = require('../../lib/client')

describe('lib/client', () => {
  describe('#handleMessage()', () => {
    it('emits error when message isn\'t JSON', async () => {
      const client = new Client()
      const promise = once(client, 'anything')

      client.handleMessage(null, null, '[')

      try {
        await promise
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Invalid message')
      }
    })

    it('emits error when decryption fails', async () => {
      const client = new Client()
      const promise = once(client, 'anything')
      const session = { decrypt: sinon.stub().throws(new Error('whoops')) }

      client.handleMessage(session, null, '{"header":"","payload":""}')

      try {
        await promise
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Decryption failed')
      }
    })
  })
})
