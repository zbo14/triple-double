'use strict'

const assert = require('assert')
const EventEmitter = require('events')
const sinon = require('sinon')
const Server = require('../../lib/server')

describe('lib/server', () => {
  describe('#validateBundle()', () => {
    it('throws if pubKey isn\'t public key', () => {
      try {
        Server.validateBundle({ pubKey: '' })
        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected bundle.pubKey to be a public key')
      }
    })

    it('throws if pubSignPreKey isn\'t public key', () => {
      try {
        Server.validateBundle({ pubKey: Buffer.alloc(32), pubSignPreKey: Buffer.alloc(31) })
        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected bundle.pubSignPreKey to be a public key')
      }
    })

    it('throws if preKeySig isn\'t signature', () => {
      try {
        Server.validateBundle({
          pubKey: Buffer.alloc(32),
          pubSignPreKey: Buffer.alloc(32),
          preKeySig: 63
        })

        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected bundle.preKeySig to be a signature')
      }
    })

    it('throws if oneTimeKeys isn\'t array of public keys', () => {
      try {
        Server.validateBundle({
          pubKey: Buffer.alloc(32),
          pubSignPreKey: Buffer.alloc(32),
          preKeySig: Buffer.alloc(64),
          oneTimeKeys: ['qrs', Buffer.alloc(32), 'tuv']
        })

        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected bundle.oneTimeKeys to be an array of public keys')
      }
    })

    it('throws if preKeySig is invalid', () => {
      const pubKey = Buffer.alloc(32, 1).toString('hex')
      const pubSignPreKey = Buffer.alloc(32, 2).toString('hex')
      const preKeySig = Buffer.alloc(64, 3).toString('hex')

      try {
        Server.validateBundle({ pubKey, pubSignPreKey, preKeySig, oneTimeKeys: [Buffer.alloc(32)] })
        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Invalid signature: bundle.preKeySig')
      }
    })
  })

  describe('#validateMessage()', () => {
    it('throws if peerKey isn\'t public key', () => {
      try {
        Server.validateMessage({ peerKey: 'A'.repeat(31) })
        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected msg.peerKey to be a public key')
      }
    })

    it('throws if pubKey isn\'t public key', () => {
      try {
        Server.validateMessage({ peerKey: Buffer.alloc(32), pubKey: {} })
        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected msg.pubKey to be a public key')
      }
    })

    it('throws if pubSignPreKey isn\'t public key', () => {
      try {
        Server.validateMessage({
          peerKey: Buffer.alloc(32),
          pubKey: Buffer.alloc(32),
          pubSignPreKey: []
        })

        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected msg.pubSignPreKey to be a public key')
      }
    })

    it('throws if ephemeralKey isn\'t non-empty string', () => {
      try {
        Server.validateMessage({
          peerKey: Buffer.alloc(32),
          pubKey: Buffer.alloc(32),
          pubSignPreKey: Buffer.alloc(32),
          ephemeralKey: 1
        })

        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected msg.ephemeralKey to be a public key')
      }
    })

    it('throws if oneTimeKey isn\'t public key', () => {
      try {
        Server.validateMessage({
          peerKey: Buffer.alloc(32),
          pubKey: Buffer.alloc(32),
          pubSignPreKey: Buffer.alloc(32),
          ephemeralKey: Buffer.alloc(32),
          oneTimeKey: Infinity
        })

        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected msg.oneTimeKey to be a public key')
      }
    })

    it('throws if header isn\'t non-empty string', () => {
      try {
        Server.validateMessage({
          peerKey: Buffer.alloc(32),
          pubKey: Buffer.alloc(32),
          pubSignPreKey: Buffer.alloc(32),
          ephemeralKey: Buffer.alloc(32),
          oneTimeKey: Buffer.alloc(32),
          header: ''
        })

        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected msg.header to be a non-empty string')
      }
    })

    it('throws if payload isn\'t non-empty string', () => {
      try {
        Server.validateMessage({
          peerKey: Buffer.alloc(32),
          pubKey: Buffer.alloc(32),
          pubSignPreKey: Buffer.alloc(32),
          ephemeralKey: Buffer.alloc(32),
          oneTimeKey: Buffer.alloc(32),
          header: 'abc',
          payload: ''
        })

        assert.fail('Should throw')
      } catch ({ message }) {
        assert.strictEqual(message, 'Expected msg.payload to be a non-empty string')
      }
    })
  })

  describe('#handleRequest()', () => {
    it('404s on unrecognized path', async () => {
      const req = { url: '/somepath' }

      const resp = {
        writeHead: sinon.stub(),
        end: sinon.stub()
      }

      const server = new Server()

      await server.handleRequest(req, resp)

      sinon.assert.calledOnce(resp.writeHead)
      sinon.assert.calledOnce(resp.end)

      sinon.assert.calledWithExactly(resp.writeHead, 404)
      sinon.assert.calledWithExactly(resp.end, 'Not Found')
    })

    it('500s on unknown error', async () => {
      const req = {}

      const resp = {
        writeHead: sinon.stub(),
        end: sinon.stub()
      }

      const server = new Server()
      const promise = EventEmitter.once(server, 'error')

      server.handleRequest = sinon.stub().rejects(new Error('whoops'))

      server.https.emit('request', req, resp)

      await promise

      sinon.assert.calledOnce(resp.writeHead)
      sinon.assert.calledOnce(resp.end)

      sinon.assert.calledWithExactly(resp.writeHead, 500)
      sinon.assert.calledWithExactly(resp.end, 'Internal Server Error')
    })
  })

  describe('#handleBundleRequest()', () => {
    it('405s when method isn\'t PUT or GET', async () => {
      const req = { method: 'POST' }

      const resp = {
        writeHead: sinon.stub(),
        end: sinon.stub()
      }

      const server = new Server()
      const promise = server.handleBundleRequest(req, resp)

      await promise

      sinon.assert.calledOnce(resp.writeHead)
      sinon.assert.calledOnce(resp.end)

      sinon.assert.calledWithExactly(resp.writeHead, 405)
      sinon.assert.calledWithExactly(resp.end, 'Method Not Allowed')
    })
  })

  describe('#handleMessageRequest()', () => {
    it('405s when method isn\'t POST or GET', async () => {
      const req = { method: 'HEAD' }

      const resp = {
        writeHead: sinon.stub(),
        end: sinon.stub()
      }

      const server = new Server()
      const promise = server.handleMessageRequest(req, resp)

      await promise

      sinon.assert.calledOnce(resp.writeHead)
      sinon.assert.calledOnce(resp.end)

      sinon.assert.calledWithExactly(resp.writeHead, 405)
      sinon.assert.calledWithExactly(resp.end, 'Method Not Allowed')
    })
  })

  describe('#handlePutBundleRequest()', () => {
    it('400s if bundle isn\'t valid JSON', async () => {
      const req = new EventEmitter()
      const resp = new EventEmitter()

      resp.writeHead = sinon.stub()
      resp.end = sinon.stub()

      const server = new Server()
      const promise = server.handlePutBundleRequest(req, resp)

      req.emit('data', 'not json"]')
      req.emit('end')

      await promise

      sinon.assert.calledOnce(resp.writeHead)
      sinon.assert.calledOnce(resp.end)

      sinon.assert.calledWithExactly(resp.writeHead, 400)
      sinon.assert.calledWithExactly(resp.end, 'Invalid bundle')
    })

    it('400s if bundle doesn\'t pass validation', async () => {
      const req = new EventEmitter()
      const resp = new EventEmitter()

      resp.writeHead = sinon.stub()
      resp.end = sinon.stub()

      const server = new Server()
      const promise = server.handlePutBundleRequest(req, resp)

      req.emit('data', '{"pubKey":""}')
      req.emit('end')

      await promise

      sinon.assert.calledOnce(resp.writeHead)
      sinon.assert.calledOnce(resp.end)

      sinon.assert.calledWithExactly(resp.writeHead, 400)
      sinon.assert.calledWithExactly(resp.end, 'Expected bundle.pubKey to be a public key')
    })
  })

  describe('#handlePostMessageRequest()', () => {
    it('400s if bundle isn\'t valid JSON', async () => {
      const req = new EventEmitter()
      const resp = new EventEmitter()

      resp.writeHead = sinon.stub()
      resp.end = sinon.stub()

      const server = new Server()
      const promise = server.handlePostMessageRequest(req, resp)

      req.emit('data', 'not json"]')
      req.emit('end')

      await promise

      sinon.assert.calledOnce(resp.writeHead)
      sinon.assert.calledOnce(resp.end)

      sinon.assert.calledWithExactly(resp.writeHead, 400)
      sinon.assert.calledWithExactly(resp.end, 'Invalid message')
    })

    it('400s if message doesn\'t pass validation', async () => {
      const req = new EventEmitter()
      const resp = new EventEmitter()

      resp.writeHead = sinon.stub()
      resp.end = sinon.stub()

      const server = new Server()
      const promise = server.handlePostMessageRequest(req, resp)

      req.emit('data', '{"peerKey":""}')
      req.emit('end')

      await promise

      sinon.assert.calledOnce(resp.writeHead)
      sinon.assert.calledOnce(resp.end)

      sinon.assert.calledWithExactly(resp.writeHead, 400)
      sinon.assert.calledWithExactly(resp.end, 'Expected msg.peerKey to be a public key')
    })
  })

  describe('#handleGetMessageRequest()', () => {
    it('400s when session ID isn\'t UUID', async () => {
      const req = { url: '/123-456-789-0' }

      const resp = {
        writeHead: sinon.stub(),
        end: sinon.stub()
      }

      const server = new Server()
      const promise = server.handleGetMessageRequest(req, resp)

      await promise

      sinon.assert.calledOnce(resp.writeHead)
      sinon.assert.calledOnce(resp.end)

      sinon.assert.calledWithExactly(resp.writeHead, 400)
      sinon.assert.calledWithExactly(resp.end, 'Session ID must be valid UUID')
    })
  })

  describe('#handleConn()', () => {
    it('404s when client id not recognized', async () => {
      const server = new Server()
      server.sessions.set('abc', ['def', 'xyz'])

      const conn = new EventEmitter()
      conn.send = sinon.stub()
      conn.close = sinon.stub()

      const data = JSON.stringify({ sid: 'abc', id: '123' })
      const promise = server.handleConn(conn)

      conn.emit('message', { data })

      await promise

      sinon.assert.calledOnce(conn.send)
      sinon.assert.calledOnce(conn.close)
      sinon.assert.calledWithExactly(conn.send, 'Not found')
    })
  })
})
