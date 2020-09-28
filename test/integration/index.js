'use strict'

const assert = require('assert')
const { once } = require('events')
const fs = require('fs')
const path = require('path')
const sinon = require('sinon')
const uuid = require('uuid')
const Client = require('../../lib/client')
const Server = require('../../lib/server')

const fixtures = path.join(__dirname, '..', 'fixtures')
const cert = fs.readFileSync(path.join(fixtures, 'cert.pem'))
const key = fs.readFileSync(path.join(fixtures, 'key.pem'))
const ca = cert

const host = 'localhost'
const port = 8888
const info = Buffer.from('some info')
const plaintext = 'just some plain ole text'

describe('integration', () => {
  before(async () => {
    this.clock = sinon.useFakeTimers()
    this.alice = new Client({ ca, host, port, info })
    this.bob = new Client({ ca, host, port, info })
    this.server = new Server({ cert, key })

    await this.server.start(port)
  })

  after(() => {
    this.clock.restore()
    this.server.stop()
  })

  describe('#publishBundle()', () => {
    it('mocks 500 error', async () => {
      const { handleRequest } = this.server
      const handleError = sinon.stub()

      this.server.once('error', handleError)
      this.server.handleRequest = sinon.stub().rejects(new Error('whoops'))

      try {
        await this.alice.publishBundle({ host, port, ca })
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Code 500: Internal Server Error')
        sinon.assert.calledOnce(handleError)
      } finally {
        this.server.handleRequest = handleRequest
      }
    })

    it('publishes bundle', async () => {
      const pubKey = await this.alice.publishBundle()
      const [[, { oneTimeKeys }]] = [...this.server.bundles]

      assert(Buffer.isBuffer(pubKey))
      assert(pubKey.equals(Buffer.from(this.alice.pubKey)))

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(oneTimeKeys.length, 10)
    })

    it('fails to re-publish same bundle', async () => {
      const pubKey = Buffer.from(this.alice.pubKey).toString('hex')
      const pubSignPreKey = Buffer.from(this.alice.pubSignPreKey).toString('hex')
      const preKeySig = Buffer.from(this.alice.preKeySig).toString('hex')
      const oneTimeKeys = this.alice.oneTimeKeys.map(({ pubKey }) => pubKey.toString('hex'))

      const headers = { 'Content-Type': 'application/json' }
      const data = JSON.stringify({ pubKey, pubSignPreKey, preKeySig, oneTimeKeys })
      const resp = await this.alice.request({ data, headers, method: 'PUT', path: '/bundle' })

      assert.strictEqual(resp.statusCode, 400)
      assert.strictEqual(resp.data, 'Cannot publish bundle with same signature')
    })
  })

  describe('#sendInitMessage()', () => {
    it('mocks 500 error when sending initial message', async () => {
      const peerKey = Buffer.from(this.alice.pubKey)
      const { handlePostMessageRequest } = this.server
      const handleError = sinon.stub()

      this.server.once('error', handleError)
      this.server.handlePostMessageRequest = sinon.stub().rejects(new Error('whoops'))

      try {
        await this.bob.sendInitMessage(peerKey, plaintext)
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Code 500: Internal Server Error')
        sinon.assert.calledOnce(handleError)
      } finally {
        this.server.handlePostMessageRequest = handlePostMessageRequest
      }
    })

    it('404s when bundle for peerKey doesn\'t exist', async () => {
      const peerKey = Buffer.from(this.alice.pubKey)
      peerKey[0]++

      try {
        await this.bob.sendInitMessage(peerKey, plaintext)
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Code 404: Not Found')
      }
    })

    it('rejects when signature invalid', async () => {
      const peerKey = Buffer.from(this.alice.pubKey)
      const [bundle] = [...this.server.bundles.values()]
      const oldPreKeySig = Buffer.from(bundle.preKeySig, 'hex')
      const newPreKeySig = Buffer.from(oldPreKeySig)
      newPreKeySig[0]++

      bundle.preKeySig = newPreKeySig.toString('hex')

      try {
        await this.bob.sendInitMessage(peerKey, plaintext)
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Invalid signature')
      } finally {
        bundle.preKeySig = oldPreKeySig.toString('hex')
      }
    })

    it('fetches bundle and sends initial message', async () => {
      const peerKey = this.alice.pubKey
      this.sid1 = await this.bob.sendInitMessage(peerKey, plaintext)

      assert(uuid.validate(this.sid1))

      assert.strictEqual(this.bob.sessions.size, 1)

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(this.server.msgs.size, 1)
      assert.strictEqual(this.server.sessions.size, 1)
      assert.strictEqual(this.server.conns.size, 0)

      const [[, { oneTimeKeys }]] = [...this.server.bundles]

      assert.strictEqual(oneTimeKeys.length, 7)
    })
  })

  describe('#recvInitMessage()', () => {
    it('fails to receive initial message with unrecognized sid', async () => {
      try {
        await this.alice.recvInitMessage(uuid.v4())
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Code 404: Not Found')
      }
    })

    it('receives initial message', async () => {
      const result = await this.alice.recvInitMessage(this.sid1)

      assert.strictEqual(result.toString(), plaintext)

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(this.server.msgs.size, 0)
      assert.strictEqual(this.server.sessions.size, 1)
      assert.strictEqual(this.server.conns.size, 0)

      assert.strictEqual(this.alice.sessions.size, 1)
      assert.strictEqual(this.bob.sessions.size, 1)
    })

    it('receives initial message after re-publishing bundle', async () => {
      const peerKey = this.alice.pubKey

      this.sid2 = await this.bob.sendInitMessage(peerKey, plaintext)
      await this.alice.publishBundle({ host, port, ca })
      const result = await this.alice.recvInitMessage(this.sid2)

      assert.strictEqual(result.toString(), plaintext)

      assert.strictEqual(this.alice.sessions.size, 2)
      assert.strictEqual(this.bob.sessions.size, 2)

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(this.server.msgs.size, 0)
      assert.strictEqual(this.server.sessions.size, 2)
      assert.strictEqual(this.server.conns.size, 0)
    })

    it('fails to find signed prekey after re-publishing multiple times', async () => {
      const peerKey = this.alice.pubKey

      const sid = await this.bob.sendInitMessage(peerKey, plaintext)
      await this.alice.publishBundle()
      await this.alice.publishBundle()

      try {
        await this.alice.recvInitMessage(sid)
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Couldn\'t determine privSignPreKey')
      }

      assert.strictEqual(this.alice.sessions.size, 2)
      assert.strictEqual(this.bob.sessions.size, 3)

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(this.server.msgs.size, 0)
      assert.strictEqual(this.server.sessions.size, 3)
      assert.strictEqual(this.server.conns.size, 0)
    })

    it('rejects if can\'t find oneTimeKey', async () => {
      const peerKey = this.alice.pubKey
      const sid = await this.bob.sendInitMessage(peerKey, plaintext)

      const msg = this.server.msgs.get(sid)
      const oneTimeKey = Buffer.from(msg.oneTimeKey, 'hex')
      oneTimeKey[1]--
      msg.oneTimeKey = oneTimeKey.toString('hex')

      try {
        await this.alice.recvInitMessage(sid)
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Couldn\'t find oneTimeKey')
      }

      assert.strictEqual(this.alice.sessions.size, 2)
      assert.strictEqual(this.bob.sessions.size, 4)

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(this.server.msgs.size, 0)
      assert.strictEqual(this.server.sessions.size, 4)
      assert.strictEqual(this.server.conns.size, 0)
    })
  })

  describe('#sendInitMessage()', () => {
    it('runs out of oneTimeKeys', async () => {
      const peerKey = this.alice.pubKey

      await this.alice.publishBundle()

      for (let i = 0; i < 10; i++) {
        await this.bob.sendInitMessage(peerKey, plaintext)
      }

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(this.server.msgs.size, 10)
      assert.strictEqual(this.server.sessions.size, 14)
      assert.strictEqual(this.server.conns.size, 0)

      try {
        await this.bob.sendInitMessage(peerKey, plaintext)
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Code 503: No more oneTimeKeys')
      }

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(this.server.msgs.size, 10)
      assert.strictEqual(this.server.sessions.size, 14)
      assert.strictEqual(this.server.conns.size, 0)
    })
  })

  describe('#connect()', () => {
    it('connects alice and bob', async () => {
      await Promise.all([
        this.alice.connect(this.sid1),
        this.bob.connect(this.sid1)
      ])

      assert.strictEqual(this.alice.conns.size, 1)
      assert.strictEqual(this.bob.conns.size, 1)

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(this.server.msgs.size, 10)
      assert.strictEqual(this.server.sessions.size, 13)
      assert.strictEqual(this.server.conns.size, 0)
    })

    it('fails to connect to same session twice', async () => {
      try {
        await this.alice.connect(this.sid1)
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Already connected')
      }
    })

    it('fails to connect if peer disconnected', async () => {
      this.alice.connect(this.sid2)

      await once(this.server, 'connection')

      const conn = this.server.conns.get(this.sid2)

      conn.close()

      try {
        await this.bob.connect(this.sid2)
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Peer disconnected')
      }
    })

    it('fails to connect if session not found', async () => {
      try {
        await this.alice.connect(uuid.v4())
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Session not found')
      }
    })
  })

  describe('#send()', () => {
    it('fails to send message to nonexistent session', async () => {
      try {
        this.alice.send(uuid.v4(), plaintext)
        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Session not found')
      }
    })

    it('sends message from bob to alice', async () => {
      const promise = once(this.alice, 'message')

      this.bob.send(this.sid1, plaintext)

      const [msg] = await promise

      assert.strictEqual(msg.sid, this.sid1)
      assert.strictEqual(msg.plaintext.toString(), plaintext)
    })

    it('sends two messages at the same time', async () => {
      const promises = [
        once(this.alice, 'message').then(([msg]) => msg),
        once(this.bob, 'message').then(([msg]) => msg)
      ]

      this.alice.send(this.sid1, plaintext)
      this.bob.send(this.sid1, plaintext)

      const plaintexts = await Promise.all(promises)

      assert.deepStrictEqual(plaintexts, [
        { plaintext: Buffer.from(plaintext), sid: this.sid1 },
        { plaintext: Buffer.from(plaintext), sid: this.sid1 }
      ])
    })

    it('sends a bunch of interleaved messages', async () => {
      const plaintext1 = Buffer.from('this is the first plaintext')
      const plaintext2 = Buffer.from('and this is the 2nd')
      const plaintext3 = Buffer.from('the last one finally')

      const promise1 = (async () => {
        const [msg1] = await once(this.alice, 'message')
        const [msg2] = await once(this.alice, 'message')
        const [msg3] = await once(this.alice, 'message')

        assert.deepStrictEqual(msg1, { plaintext: plaintext1, sid: this.sid1 })
        assert.deepStrictEqual(msg2, { plaintext: plaintext2, sid: this.sid1 })
        assert.deepStrictEqual(msg3, { plaintext: plaintext3, sid: this.sid1 })
      })()

      const promise2 = (async () => {
        const [msg1] = await once(this.bob, 'message')
        const [msg2] = await once(this.bob, 'message')
        const [msg3] = await once(this.bob, 'message')

        assert.deepStrictEqual(msg1, { plaintext: plaintext1, sid: this.sid1 })
        assert.deepStrictEqual(msg2, { plaintext: plaintext2, sid: this.sid1 })
        assert.deepStrictEqual(msg3, { plaintext: plaintext3, sid: this.sid1 })
      })()

      this.alice.send(this.sid1, plaintext1)
      this.bob.send(this.sid1, plaintext1)
      this.alice.send(this.sid1, plaintext2)
      this.alice.send(this.sid1, plaintext3)
      this.bob.send(this.sid1, plaintext2)
      this.bob.send(this.sid1, plaintext3)

      await Promise.all([promise1, promise2])
    })
  })

  describe('cleanup', () => {
    it('cleans up sessions and messages on server', () => {
      this.clock.tick(60e3)

      assert.strictEqual(this.server.bundles.size, 1)
      assert.strictEqual(this.server.msgs.size, 0)
      assert.strictEqual(this.server.sessions.size, 0)
    })
  })
})
