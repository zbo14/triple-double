'use strict'

const assert = require('assert')
const { randomBytes } = require('tweetnacl')
const Session = require('../../lib/session')

describe('lib/session', () => {
  describe('#init()', () => {
    beforeEach(() => {
      this.alice = new Session()
      this.bob = new Session()

      this.ad = Buffer.from('some additional data')
      this.info = Buffer.from('some info')

      this.secKeys = [
        randomBytes(32),
        randomBytes(32),
        randomBytes(32)
      ]
    })

    it('tests initialization', () => {
      const peerKey = this.alice.init(this)

      this.bob.init({ ...this, peerKey })

      assert(peerKey.equals(this.bob.peerKey))

      assert.strictEqual(this.alice.sendChainKey, null)
      assert.strictEqual(this.alice.recvChainKey, null)
      assert.strictEqual(this.alice.sendHeaderKey, null)
      assert.strictEqual(this.alice.recvHeaderKey, null)

      assert(this.alice.sendNextHeaderKey.equals(this.bob.recvNextHeaderKey))
      assert(this.alice.recvNextHeaderKey.equals(this.bob.sendHeaderKey))

      assert(Buffer.isBuffer(this.bob.sendChainKey))
      assert.strictEqual(this.bob.recvChainKey, null)
      assert(Buffer.isBuffer(this.bob.sendNextHeaderKey))
    })
  })

  describe('#encrypt()', () => {
    beforeEach(() => {
      this.alice = new Session()
      this.bob = new Session()

      this.ad = Buffer.from('some additional data')
      this.info = Buffer.from('some info')

      this.secKeys = [
        randomBytes(32),
        randomBytes(32),
        randomBytes(32)
      ]

      const peerKey = this.alice.init(this)

      this.bob.init({ ...this, peerKey })
    })

    it('can\'t encrypt message yet', () => {
      const plaintext = Buffer.from('just some plaintext')

      try {
        this.alice.encrypt(plaintext)
        assert.fail('Should reject')
      } catch ({ message }) {
        assert(message.includes('Received null'))
      }
    })

    it('encrypts message', () => {
      assert.strictEqual(this.alice.sendMsgNum, 0)

      const {
        rootKey,
        sendChainKey,
        recvChainKey
      } = this.bob

      const plaintext = Buffer.from('just some plaintext')
      const { header, payload } = this.bob.encrypt(plaintext)

      assert(Buffer.isBuffer(header))
      assert(Buffer.isBuffer(payload))

      assert.strictEqual(this.bob.recvMsgNum, 0)
      assert.strictEqual(this.bob.sendMsgNum, 1)
      assert.strictEqual(this.bob.prevChainLen, 0)

      assert(this.bob.rootKey.equals(rootKey))
      assert(!this.bob.sendChainKey.equals(sendChainKey))
      assert.strictEqual(this.bob.recvChainKey, recvChainKey)
    })
  })

  describe('#decrypt', () => {
    beforeEach(() => {
      this.alice = new Session()
      this.bob = new Session()
      this.info = Buffer.from('some info')
      this.ad = Buffer.from('some additional data')
      this.plaintext = Buffer.from('just some plaintext')

      this.secKeys = [
        randomBytes(32),
        randomBytes(32),
        randomBytes(32)
      ]

      const peerKey = this.alice.init(this)

      this.bob.init({ ...this, peerKey })

      const { header, payload } = this.bob.encrypt(this.plaintext)

      this.header = header
      this.payload = payload
    })

    it('throws if HMAC invalid', () => {
      ++this.payload[this.payload.byteLength - 1]

      try {
        this.alice.decrypt(this)
        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Invalid HMAC')
      }
    })

    it('throws when MAX_SKIP exceeded', () => {
      for (let i = 0; i < Session.MAX_SKIP; i++) {
        this.bob.encrypt(this.plaintext)
      }

      const { header, payload } = this.bob.encrypt(this.plaintext)

      try {
        this.alice.decrypt({ header, payload })
        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Cannot skip that many messages')
      }
    })

    it('throws if it can\'t decrypt header', () => {
      ++this.header[this.header.byteLength - 1]

      try {
        this.alice.decrypt(this)
        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Failed to decrypt header')
      }
    })

    it('decrypts message', () => {
      const {
        rootKey,
        sendChainKey,
        sendNextHeaderKey,
        recvNextHeaderKey
      } = this.alice

      const plaintext = this.alice.decrypt(this)

      assert(plaintext.equals(this.plaintext))

      assert(!this.alice.rootKey.equals(rootKey))
      assert(!this.alice.sendChainKey.equals(sendChainKey || Buffer.alloc(0)))
      assert(this.alice.sendHeaderKey.equals(sendNextHeaderKey))
      assert(!this.alice.sendNextHeaderKey.equals(sendNextHeaderKey))
      assert(this.alice.recvHeaderKey.equals(recvNextHeaderKey))
      assert(this.alice.recvHeaderKey.equals(this.bob.sendHeaderKey))
      assert(!this.alice.recvNextHeaderKey.equals(recvNextHeaderKey))
      assert(this.alice.recvNextHeaderKey.equals(this.bob.sendNextHeaderKey))
      assert(this.alice.recvChainKey.equals(this.bob.sendChainKey))

      assert.strictEqual(this.alice.sendMsgNum, 0)
      assert.strictEqual(this.alice.recvMsgNum, 1)
      assert.strictEqual(this.alice.prevChainLen, 0)
      assert.deepStrictEqual(this.alice.skippedMsgs, [])
    })

    it('decrypts message and sets peerKey/recvChain', () => {
      this.alice.decrypt(this)

      const { header, payload } = this.alice.encrypt(this.plaintext)

      this.header = header
      this.payload = payload

      const {
        rootKey,
        sendChainKey,
        recvChainKey,
        sendNextHeaderKey,
        recvNextHeaderKey
      } = this.bob

      const plaintext = this.bob.decrypt(this)

      assert(plaintext.equals(this.plaintext))
      assert(this.bob.peerKey.equals(this.alice.pubKey))
      assert(!this.bob.rootKey.equals(rootKey))
      assert(!this.bob.sendChainKey.equals(sendChainKey))
      assert(this.bob.sendHeaderKey.equals(sendNextHeaderKey))
      assert(!this.bob.sendNextHeaderKey.equals(sendNextHeaderKey))
      assert(this.bob.recvHeaderKey.equals(recvNextHeaderKey))
      assert(this.bob.recvHeaderKey.equals(this.alice.sendHeaderKey))
      assert(!this.bob.recvNextHeaderKey.equals(recvNextHeaderKey))
      assert(this.bob.recvNextHeaderKey.equals(this.alice.sendNextHeaderKey))
      assert.notStrictEqual(this.bob.recvChainKey, recvChainKey)
      assert(this.bob.recvChainKey.equals(this.alice.sendChainKey))

      assert.strictEqual(this.bob.sendMsgNum, 0)
      assert.strictEqual(this.bob.recvMsgNum, 1)
      assert.strictEqual(this.bob.prevChainLen, 1)
      assert.deepStrictEqual(this.bob.skippedMsgs, [])
    })

    it('skips message and decrypts another one', () => {
      const { header, payload } = this.bob.encrypt(this.plaintext)

      this.header = header
      this.payload = payload

      const {
        rootKey,
        sendChainKey,
        recvChainKey
      } = this.alice

      const plaintext = this.alice.decrypt(this)

      assert(plaintext.equals(this.plaintext))

      assert(!this.alice.rootKey.equals(rootKey))
      assert(!this.alice.sendChainKey.equals(sendChainKey || Buffer.alloc(0)))
      assert(!this.alice.recvChainKey.equals(recvChainKey || Buffer.alloc(0)))
      assert(this.alice.recvChainKey.equals(this.bob.sendChainKey))
      assert(this.alice.recvHeaderKey.equals(this.bob.sendHeaderKey))
      assert(this.alice.recvNextHeaderKey.equals(this.bob.sendNextHeaderKey))
      assert(this.alice.sendHeaderKey.equals(this.bob.recvNextHeaderKey))

      assert.strictEqual(this.bob.sendMsgNum, 2)
      assert.strictEqual(this.bob.recvMsgNum, 0)
      assert.strictEqual(this.bob.prevChainLen, 0)
      assert.deepStrictEqual(this.bob.skippedMsgs, [])

      assert.strictEqual(this.alice.sendMsgNum, 0)
      assert.strictEqual(this.alice.recvMsgNum, 2)
      assert.strictEqual(this.alice.prevChainLen, 0)
      assert.strictEqual(this.alice.skippedMsgs.length, 1)

      const [{ msgNum }] = this.alice.skippedMsgs

      assert.strictEqual(msgNum, 0)
    })

    it('skips message and decrypts skipped message', () => {
      const { header, payload } = this.bob.encrypt(this.plaintext)

      const {
        rootKey,
        sendChainKey,
        recvChainKey
      } = this.alice

      this.alice.decrypt({ header, payload })

      const plaintext = this.alice.decrypt(this)

      assert(plaintext.equals(this.plaintext))
      assert(!this.alice.rootKey.equals(rootKey))
      assert(!this.alice.sendChainKey.equals(sendChainKey || Buffer.alloc(0)))
      assert(!this.alice.recvChainKey.equals(recvChainKey || Buffer.alloc(0)))
      assert(this.alice.recvChainKey.equals(this.bob.sendChainKey))

      assert.strictEqual(this.bob.sendMsgNum, 2)
      assert.strictEqual(this.bob.recvMsgNum, 0)
      assert.strictEqual(this.bob.prevChainLen, 0)
      assert.deepStrictEqual(this.bob.skippedMsgs, [])

      assert.strictEqual(this.alice.sendMsgNum, 0)
      assert.strictEqual(this.alice.recvMsgNum, 2)
      assert.strictEqual(this.alice.prevChainLen, 0)
      assert.deepStrictEqual(this.alice.skippedMsgs, [])
    })

    it('skips a bunch of messages and decrypts them out of order', () => {
      const msg1 = this.bob.encrypt(this.plaintext)
      const msg2 = this.bob.encrypt(this.plaintext)
      const msg3 = this.bob.encrypt(this.plaintext)
      const msg4 = this.bob.encrypt(this.plaintext)
      const msg5 = this.bob.encrypt(this.plaintext)

      const plaintext1 = this.alice.decrypt(msg5)
      const plaintext2 = this.alice.decrypt(msg2)
      const plaintext3 = this.alice.decrypt(msg1)
      const plaintext4 = this.alice.decrypt(msg4)
      const plaintext5 = this.alice.decrypt(msg3)

      assert.strictEqual(this.alice.sendMsgNum, 0)
      assert.strictEqual(this.alice.recvMsgNum, 6)
      assert.strictEqual(this.alice.prevChainLen, 0)
      assert.strictEqual(this.alice.skippedMsgs.length, 1)

      const [{ msgNum }] = this.alice.skippedMsgs

      assert.strictEqual(msgNum, 0)

      assert.deepStrictEqual([
        plaintext1,
        plaintext2,
        plaintext3,
        plaintext4,
        plaintext5
      ], Array.from({ length: 5 }).map(() => this.plaintext))
    })

    it('exchanges some messages', () => {
      this.alice.decrypt(this)

      const result1 = this.alice.encrypt(this.plaintext)

      this.bob.decrypt(result1)

      const result2 = this.bob.encrypt(this.plaintext)

      const {
        rootKey,
        sendChainKey,
        recvChainKey,
        sendHeaderKey,
        recvHeaderKey,
        recvNextHeaderKey
      } = this.alice

      const plaintext = this.alice.decrypt(result2)

      assert(plaintext.equals(this.plaintext))
      assert(!this.alice.rootKey.equals(rootKey))
      assert(!this.alice.sendChainKey.equals(sendChainKey))
      assert(!this.alice.recvChainKey.equals(recvChainKey))
      assert(this.alice.recvChainKey.equals(this.bob.sendChainKey))
      assert(!this.alice.sendHeaderKey.equals(sendHeaderKey))
      assert(!this.alice.recvHeaderKey.equals(recvHeaderKey))
      assert(this.alice.recvHeaderKey.equals(this.bob.sendHeaderKey))
      assert(!this.alice.recvNextHeaderKey.equals(recvNextHeaderKey))
      assert(this.alice.recvNextHeaderKey.equals(this.bob.sendNextHeaderKey))

      assert.strictEqual(this.bob.sendMsgNum, 1)
      assert.strictEqual(this.bob.recvMsgNum, 1)
      assert.strictEqual(this.bob.prevChainLen, 1)
      assert.deepStrictEqual(this.bob.skippedMsgs, [])

      assert.strictEqual(this.alice.sendMsgNum, 0)
      assert.strictEqual(this.alice.recvMsgNum, 1)
      assert.strictEqual(this.alice.prevChainLen, 1)
      assert.deepStrictEqual(this.alice.skippedMsgs, [])
    })

    it('exchanges a bunch of messages', () => {
      this.bob.encrypt(this.plaintext)
      this.bob.encrypt(this.plaintext)

      const msg1 = this.bob.encrypt(this.plaintext)
      const plaintext1 = this.alice.decrypt(msg1)

      assert.strictEqual(this.alice.sendMsgNum, 0)
      assert.strictEqual(this.alice.recvMsgNum, 4)
      assert.strictEqual(this.alice.prevChainLen, 0)
      assert.strictEqual(this.alice.skippedMsgs.length, 3)

      const msg2 = this.alice.encrypt(this.plaintext)
      const msg3 = this.bob.encrypt(this.plaintext)

      const plaintext2 = this.bob.decrypt(msg2)

      assert.strictEqual(this.bob.sendMsgNum, 0)
      assert.strictEqual(this.bob.recvMsgNum, 1)
      assert.strictEqual(this.bob.prevChainLen, 5)
      assert.strictEqual(this.bob.skippedMsgs.length, 0)

      const msg4 = this.bob.encrypt(this.plaintext)
      const plaintext3 = this.alice.decrypt(msg4)

      assert.strictEqual(this.alice.sendMsgNum, 0)
      assert.strictEqual(this.alice.recvMsgNum, 1)
      assert.strictEqual(this.alice.prevChainLen, 1)
      assert.strictEqual(this.alice.skippedMsgs.length, 4)

      const plaintext4 = this.alice.decrypt(msg3)

      assert.strictEqual(this.alice.sendMsgNum, 0)
      assert.strictEqual(this.alice.recvMsgNum, 1)
      assert.strictEqual(this.alice.prevChainLen, 1)
      assert.strictEqual(this.alice.skippedMsgs.length, 3)

      const msg5 = this.alice.encrypt(this.plaintext)
      const plaintext5 = this.bob.decrypt(msg5)

      assert.strictEqual(this.bob.sendMsgNum, 0)
      assert.strictEqual(this.bob.recvMsgNum, 1)
      assert.strictEqual(this.bob.prevChainLen, 1)
      assert.strictEqual(this.bob.skippedMsgs.length, 0)

      assert.deepStrictEqual([
        plaintext1,
        plaintext2,
        plaintext3,
        plaintext4,
        plaintext5
      ], Array.from({ length: 5 }).map(() => this.plaintext))
    })
  })
})
