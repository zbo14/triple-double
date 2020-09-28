'use strict'

const axl = require('axl')
const EventEmitter = require('events')
const https = require('https')
const uuid = require('uuid')
const WebSocket = require('ws')
const util = require('./util')

/**
 * This class implements an HTTPS/WebSocket server that facilitates secret negotation
 * and establishes secure channels between clients.
 */
class Server extends EventEmitter {
  constructor (opts) {
    super()

    this.bundles = new Map()
    this.msgs = new Map()
    this.sessions = new Map()
    this.conns = new Map()
    this.timeouts = new Map()

    const server = this.https = https.createServer(opts, async (req, resp) => {
      try {
        await this.handleRequest(req, resp)
      } catch (err) {
        resp.writeHead(500)
        resp.end('Internal Server Error')
        this.emit('error', err)
      }
    })

    this.ws = new WebSocket.Server({ server })
      .on('connection', this.handleConn.bind(this))
  }

  static async readRequestData (req) {
    let data = ''

    req.on('data', chunk => {
      data += chunk
    })

    await EventEmitter.once(req, 'end')

    return data
  }

  static validateBundle (bundle) {
    util.validate(
      ['bundle.pubKey', 'a public key', bundle.pubKey],
      ['bundle.pubSignPreKey', 'a public key', bundle.pubSignPreKey],
      ['bundle.preKeySig', 'a signature', bundle.preKeySig],
      ['bundle.oneTimeKeys', 'an array of public keys', bundle.oneTimeKeys]
    )

    const pubKey = Buffer.from(bundle.pubKey, 'hex')
    const pubSignPreKey = Buffer.from(bundle.pubSignPreKey, 'hex')
    const preKeySig = Buffer.from(bundle.preKeySig, 'hex')
    const valid = axl.verify(pubKey, pubSignPreKey, preKeySig)

    if (!valid) {
      throw new Error('Invalid signature: bundle.preKeySig')
    }
  }

  static validateMessage (msg) {
    util.validate(
      ['msg.peerKey', 'a public key', msg.peerKey],
      ['msg.pubKey', 'a public key', msg.pubKey],
      ['msg.pubSignPreKey', 'a public key', msg.pubSignPreKey],
      ['msg.ephemeralKey', 'a public key', msg.ephemeralKey],
      ['msg.oneTimeKey', 'a public key', msg.oneTimeKey],
      ['msg.header', 'a non-empty string', msg.header],
      ['msg.payload', 'a non-empty string', msg.payload]
    )
  }

  /**
   * Start the HTTPS/WebSocket servers.
   *
   * @param  {...*} args - arguments to https.server.listen()
   *
   * @return {Promise}
   */
  start (...args) {
    return new Promise((resolve, reject) => {
      this.https
        .once('error', reject)
        .listen(...args, resolve)
    })
  }

  /**
   * Stop the HTTPS/WebSocket servers.
   */
  stop () {
    this.ws.close()
    this.https.close()
  }

  async handleConn (conn) {
    const [{ data }] = await EventEmitter.once(conn, 'message')
    const { id, sid } = JSON.parse(data)
    let ids = this.sessions.get(sid)

    if (!ids || !ids.includes(id)) {
      conn.send('Not found')
      conn.close()
      return
    }

    ids = ids.filter(_ => _ !== id)

    if (ids.length) {
      this.conns.set(sid, conn)
      this.sessions.set(sid, ids)
      this.emit('connection', conn)
      conn.once('close', () => this.conns.delete(sid))
      return
    }

    const peerConn = this.conns.get(sid)
    const timeout = this.timeouts.get(sid)

    clearTimeout(timeout)

    this.conns.delete(sid)
    this.sessions.delete(sid)
    this.timeouts.delete(sid)

    if (!peerConn) {
      conn.send('Peer disconnected')
      conn.close()
      return
    }

    this.emit('connection', conn)

    conn.send('OK')
    peerConn.send('OK')

    conn.on('message', msg => peerConn.send(msg))
    peerConn.on('message', msg => conn.send(msg))
  }

  async handleRequest (req, resp) {
    if (req.url.startsWith('/bundle')) {
      await this.handleBundleRequest(req, resp)
      return
    }

    if (req.url.startsWith('/message')) {
      await this.handleMessageRequest(req, resp)
      return
    }

    resp.writeHead(404)
    resp.end('Not Found')
  }

  async handleBundleRequest (req, resp) {
    if (req.method === 'GET') {
      await this.handleGetBundleRequest(req, resp)
      return
    }
    if (req.method === 'PUT') {
      await this.handlePutBundleRequest(req, resp)
      return
    }

    resp.writeHead(405)
    resp.end('Method Not Allowed')
  }

  async handleGetBundleRequest (req, resp) {
    const id = req.url.split('/bundle/')[1]
    const bundle = this.bundles.get(id)

    if (!bundle) {
      resp.writeHead(404)
      resp.end('Not Found')
      return
    }

    const { pubSignKey, pubSignPreKey, preKeySig } = bundle
    const oneTimeKey = bundle.oneTimeKeys.shift()

    if (!oneTimeKey) {
      resp.writeHead(503)
      resp.end('No more oneTimeKeys')
      return
    }

    await this.bundles.set(bundle.pubKey, bundle)

    const data = JSON.stringify({
      pubSignKey,
      pubSignPreKey,
      preKeySig,
      oneTimeKey
    })

    resp.end(data)
  }

  async handlePutBundleRequest (req, resp) {
    const data = await Server.readRequestData(req)

    let bundle

    try {
      bundle = JSON.parse(data)
    } catch {
      resp.writeHead(400)
      resp.end('Invalid bundle')
      return
    }

    try {
      Server.validateBundle(bundle)
    } catch ({ message }) {
      resp.writeHead(400)
      resp.end(message)
      return
    }

    const oldBundle = this.bundles.get(bundle.pubKey)

    if (oldBundle && oldBundle.preKeySig === bundle.preKeySig) {
      resp.writeHead(400)
      resp.end('Cannot publish bundle with same signature')
      return
    }

    await this.bundles.set(bundle.pubKey, bundle)

    resp.writeHead(201)
    resp.end()
  }

  async handleMessageRequest (req, resp) {
    if (req.method === 'GET') {
      await this.handleGetMessageRequest(req, resp)
      return
    }

    if (req.method === 'POST') {
      await this.handlePostMessageRequest(req, resp)
      return
    }

    resp.writeHead(405)
    resp.end('Method Not Allowed')
  }

  async handleGetMessageRequest (req, resp) {
    const sid = req.url.split('/message/')[1]

    if (!uuid.validate(sid)) {
      resp.writeHead(400)
      resp.end('Session ID must be valid UUID')
      return
    }

    const msg = this.msgs.get(sid)

    if (!msg) {
      resp.writeHead(404)
      resp.end('Not Found')
      return
    }

    this.msgs.delete(sid)

    const data = JSON.stringify(msg)

    resp.end(data)
  }

  async handlePostMessageRequest (req, resp) {
    const data = await Server.readRequestData(req)

    let msg

    try {
      msg = JSON.parse(data)
    } catch {
      resp.writeHead(400)
      resp.end('Invalid message')
      return
    }

    try {
      Server.validateMessage(msg)
    } catch ({ message }) {
      resp.writeHead(400)
      resp.end(message)
      return
    }

    const sid = uuid.v4()

    this.msgs.set(sid, msg)
    this.sessions.set(sid, [msg.peerKey, msg.pubKey])

    resp.writeHead(201)
    resp.end(sid)

    const timeout = setTimeout(() => {
      this.msgs.delete(sid)
      this.sessions.delete(sid)
      this.timeouts.delete(sid)
    }, 60e3)

    this.timeouts.set(sid, timeout)
  }
}

module.exports = Server
