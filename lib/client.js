'use strict'

const axl = require('axl')
const EventEmitter = require('events')
const https = require('https')
const nacl = require('tweetnacl')
const WebSocket = require('ws')
const Session = require('./session')
const util = require('./util')

/**
 * This class implements a client that negotiates secrets with and securely sends messages to other clients via a server.
 * A client can have multiple peers, each corresponding to a unique session.
 */
class Client extends EventEmitter {
  constructor () {
    super()

    const seed = nacl.randomBytes(32)
    const kp = axl.generateKeyPair(seed)

    this.pubKey = kp.public
    this.privKey = kp.private

    this.id = Client.id(this.pubKey)

    this.pubSignPreKey = null
    this.privSignPreKey = null
    this.preKeySig = null
    this.prevSignPreKey = null

    this.oneTimeKeys = []
    this.sessions = new Map()
    this.conns = new Map()
  }

  static id (pubKey) {
    return encodeURIComponent(Buffer.from(pubKey).toString('base64'))
  }

  static request (opts) {
    return new Promise((resolve, reject) => {
      https.request(opts, resp => {
        const { statusCode, headers } = resp

        let data = ''

        resp
          .on('data', chunk => {
            data += chunk
          })
          .once('end', () => resolve({ statusCode, headers, data }))
          .once('error', reject)
      }).once('error', reject)
        .end(opts.data || '')
    })
  }

  /**
   * Open a WebSocket connection to the server for a given session.
   *
   * @param  {Object}           args
   * @param  {String}           args.host - the server host
   * @param  {Number}           args.port - the server port
   * @param  {String}           args.sid  - the session ID
   * @param  {(Buffer|String)}  args.ca   - the server's TLS certificate
   *
   * @return {Promise}
   */
  async connect ({ host, port, sid, ca }) {
    util.validate(
      ['args.host', 'a non-empty string', host],
      ['args.port', 'a valid port number', port],
      ['args.sid', 'a UUID', sid],
      ['args.ca', 'a buffer or string', ca]
    )

    const session = this.sessions.get(sid)

    if (!session) {
      throw new Error('Session not found')
    }

    let conn = this.conns.get(sid)

    if (conn) {
      throw new Error('Already connected')
    }

    conn = new WebSocket(`wss://${host}:${port}`, { ca })

    await EventEmitter.once(conn, 'open')

    const msg = JSON.stringify({ id: decodeURIComponent(this.id), sid })

    conn.send(msg)

    const [{ data }] = await EventEmitter.once(conn, 'message')

    if (data !== 'OK') {
      throw new Error(data)
    }

    this.conns.set(sid, conn)

    conn.on('message', this.handleMessage.bind(this, session, sid))
  }

  /**
   * Encrypt a plaintext and send it to peer in session.
   *
   * @param  {Object}           args
   * @param  {(Buffer|String)}  args.plaintext - the plaintext to encrypt and send
   * @param  {String}           args.sid       - the session id
   */
  send ({ plaintext, sid }) {
    util.validate(
      ['args.plaintext', 'a buffer or string', plaintext],
      ['args.sid', 'a UUID', sid]
    )

    const session = this.sessions.get(sid)

    if (!session) {
      throw new Error('Session not found')
    }

    const conn = this.conns.get(sid)
    let { header, payload } = session.encrypt(plaintext)
    header = header.toString('base64')
    payload = payload.toString('base64')
    const msg = JSON.stringify({ header, payload })

    conn.send(msg)
  }

  /**
   * Publish bundle to server.
   *
   * @param  {Object}           args
   * @param  {String}           args.host - the server host
   * @param  {Number}           args.port - the server port
   * @param  {(Buffer|String)}  args.ca   - the server's TLS certificate
   *
   * @return {Promise}
   */
  async publishBundle ({ host, port, ca }) {
    util.validate(
      ['args.host', 'a non-empty string', host],
      ['args.port', 'a valid port number', port],
      ['args.ca', 'a buffer or string', ca]
    )

    if (this.privSignPreKey) {
      this.prevSignPreKey = {
        pubKey: this.pubSignPreKey,
        privKey: this.privSignPreKey
      }
    }

    {
      const { pubKey, privKey } = util.genKeyPair()
      this.pubSignPreKey = pubKey
      this.privSignPreKey = privKey
    }

    const random = nacl.randomBytes(64)
    this.preKeySig = axl.sign(this.privKey, this.pubSignPreKey, random)

    let oneTimeKeys = []

    for (let i = 0; i < 10; i++) {
      const { pubKey, privKey } = util.genKeyPair()
      oneTimeKeys.push({ pubKey, privKey })
    }

    this.oneTimeKeys.push(...oneTimeKeys)

    const pubKey = Buffer.from(this.pubKey).toString('base64')
    const pubSignPreKey = Buffer.from(this.pubSignPreKey).toString('base64')
    const preKeySig = Buffer.from(this.preKeySig).toString('base64')
    oneTimeKeys = oneTimeKeys.map(({ pubKey }) => pubKey.toString('base64'))

    const headers = { 'Content-Type': 'application/json' }
    const data = JSON.stringify({ pubKey, pubSignPreKey, preKeySig, oneTimeKeys })
    const resp = await Client.request({ data, host, port, headers, method: 'PUT', path: '/bundle', ca })

    if (resp.statusCode !== 201) {
      throw new Error(`Code ${resp.statusCode}: ${resp.data}`)
    }

    return Buffer.from(this.pubKey)
  }

  /**
   * Fetch peer bundle from server and send initial message to establish session.
   *
   * @param  {Object}           args
   * @param  {(Buffer|String)}  args.plaintext - initial plaintext to encrypt and send
   * @param  {Buffer}           args.peerKey   - the peer's public key
   * @param  {Buffer}           args.info      - additional info
   * @param  {String}           args.host      - the server host
   * @param  {Number}           args.port      - the server port
   * @param  {(Buffer|String)}  args.ca        - the server's TLS certificate
   *
   * @return {Promise}
   */
  async sendInitMessage ({ plaintext, peerKey, info, host, port, ca }) {
    util.validate(
      ['args.host', 'a non-empty string', host],
      ['args.port', 'a valid port number', port],
      ['args.plaintext', 'a buffer or string', plaintext],
      ['args.peerKey', 'a public key', peerKey],
      ['args.info', 'a buffer', info],
      ['args.ca', 'a buffer or string', ca]
    )

    const id = Client.id(peerKey)
    const path = '/bundle/' + id
    let resp = await Client.request({ host, port, path, ca })

    if (resp.statusCode !== 200) {
      throw new Error(`Code ${resp.statusCode}: ${resp.data}`)
    }

    const bundle = JSON.parse(resp.data)
    let pubSignPreKey = Buffer.from(bundle.pubSignPreKey, 'base64')
    const preKeySig = Buffer.from(bundle.preKeySig, 'base64')
    const valid = axl.verify(peerKey, pubSignPreKey, preKeySig)

    if (!valid) {
      throw new Error('Invalid signature')
    }

    const ephemeral = util.genKeyPair()
    let oneTimeKey = Buffer.from(bundle.oneTimeKey, 'base64')

    const dhs = [
      nacl.scalarMult(this.privKey, pubSignPreKey),
      nacl.scalarMult(ephemeral.privKey, peerKey),
      nacl.scalarMult(ephemeral.privKey, pubSignPreKey),
      nacl.scalarMult(ephemeral.privKey, oneTimeKey)
    ]

    const ad = Buffer.concat([this.pubKey, peerKey])
    const ikm = Buffer.concat([Buffer.alloc(32, 0xFF), ...dhs])
    let okm = util.hkdf({ ikm, info, length: 96 })
    const secKeys = []

    for (let i = 0; i < 3; i++) {
      secKeys.push(okm.slice(0, 32))
      okm = okm.slice(32)
    }

    const session = new Session()

    session.init({ ad, info, keyPair: this, peerKey, secKeys })

    let { header, payload } = await session.encrypt(plaintext)

    const pubKey = Buffer.from(this.pubKey).toString('base64')
    const ephemeralKey = Buffer.from(ephemeral.pubKey).toString('base64')
    pubSignPreKey = pubSignPreKey.toString('base64')
    peerKey = Buffer.from(peerKey).toString('base64')
    oneTimeKey = oneTimeKey.toString('base64')
    header = header.toString('base64')
    payload = payload.toString('base64')

    const data = JSON.stringify({ pubKey, peerKey, pubSignPreKey, ephemeralKey, oneTimeKey, header, payload })
    const headers = { 'Content-Type': 'application/json' }
    resp = await Client.request({ data, host, port, headers, method: 'POST', path: '/message', ca })

    if (resp.statusCode !== 201) {
      throw new Error(`Code ${resp.statusCode}: ${resp.data}`)
    }

    this.sessions.set(resp.data, session)

    return resp.data
  }

  /**
   * Receive initial message from server to establish session with peer.
   *
   * @param  {Object}           args
   * @param  {Buffer}           args.info - additional info
   * @param  {String}           args.host - the server host
   * @param  {Number}           args.port - the server port
   * @param  {String}           args.sid  - the session ID
   * @param  {(Buffer|String)}  args.ca   - the server's TLS certificate
   *
   * @return {Promise}
   */
  async recvInitMessage ({ info, host, port, sid, ca }) {
    util.validate(
      ['args.host', 'a non-empty string', host],
      ['args.port', 'a valid port number', port],
      ['args.sid', 'a UUID', sid],
      ['args.info', 'a buffer', info],
      ['args.ca', 'a buffer or string', ca]
    )

    const path = '/message/' + sid
    const resp = await Client.request({ host, port, path, ca })

    if (resp.statusCode !== 200) {
      throw new Error(`Code ${resp.statusCode}: ${resp.data}`)
    }

    const msg = JSON.parse(resp.data)
    const pubKey = Buffer.from(msg.pubKey, 'base64')
    const pubSignPreKey = Buffer.from(msg.pubSignPreKey, 'base64')
    const ephemeralKey = Buffer.from(msg.ephemeralKey, 'base64')
    let oneTimeKey = Buffer.from(msg.oneTimeKey, 'base64')
    const header = Buffer.from(msg.header, 'base64')
    const payload = Buffer.from(msg.payload, 'base64')

    let privSignPreKey

    if (pubSignPreKey.equals(this.pubSignPreKey)) {
      ({ privSignPreKey } = this)
    } else if (this.prevSignPreKey && pubSignPreKey.equals(this.prevSignPreKey.pubKey)) {
      privSignPreKey = this.prevSignPreKey.privKey
    } else {
      throw new Error('Couldn\'t determine privSignPreKey')
    }

    oneTimeKey = this.oneTimeKeys.find(({ pubKey }) => oneTimeKey.equals(pubKey))

    if (!oneTimeKey) {
      throw new Error('Couldn\'t find oneTimeKey')
    }

    this.oneTimeKeys = this.oneTimeKeys.filter(({ pubKey }) => !oneTimeKey.pubKey.equals(pubKey))

    const dhs = [
      nacl.scalarMult(privSignPreKey, pubKey),
      nacl.scalarMult(this.privKey, ephemeralKey),
      nacl.scalarMult(privSignPreKey, ephemeralKey),
      nacl.scalarMult(oneTimeKey.privKey, ephemeralKey)
    ]

    const ad = Buffer.concat([pubKey, this.pubKey])
    const ikm = Buffer.concat([Buffer.alloc(32, 0xFF), ...dhs])
    let okm = util.hkdf({ ikm, info, length: 96 })
    const secKeys = []

    for (let i = 0; i < 3; i++) {
      secKeys.push(okm.slice(0, 32))
      okm = okm.slice(32)
    }

    const session = new Session()

    session.init({ ad, info, keyPair: this, secKeys })
    this.sessions.set(sid, session)

    return session.decrypt({ header, payload })
  }

  handleMessage (session, sid, msg) {
    try {
      msg = JSON.parse(msg)
    } catch {
      this.emit('error', new Error('Invalid message'))
      return
    }

    const header = Buffer.from(msg.header, 'base64')
    const payload = Buffer.from(msg.payload, 'base64')

    try {
      const plaintext = session.decrypt({ header, payload })
      this.emit('message', { sid, plaintext })
    } catch {
      this.emit('error', new Error('Decryption failed'))
    }
  }
}

module.exports = Client
