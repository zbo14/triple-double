'use strict'

const axl = require('axl')
const EventEmitter = require('events')
const https = require('https')
const nacl = require('tweetnacl')
const WebSocket = require('ws')
const Session = require('./session')
const util = require('./util')

const INFO = Buffer.from('triple-double')

/**
 * This class implements a client that negotiates secrets with and securely sends messages to other clients via a server.
 * A client can have multiple peers, each corresponding to a unique session.
 */
class Client extends EventEmitter {
  constructor ({ ca, host, port, info = INFO }) {
    util.validate(
      ['args.ca', 'a buffer or string', ca],
      ['args.host', 'a non-empty string', host],
      ['args.port', 'a valid port number', port],
      ['args.info', 'a buffer', info]
    )

    super()

    this.ca = ca
    this.host = host
    this.port = port
    this.info = info

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
    return Buffer.from(pubKey).toString('hex')
  }

  request (opts) {
    return new Promise((resolve, reject) => {
      https.request({
        ...opts,
        ca: this.ca,
        host: this.host,
        port: this.port
      }, resp => {
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
   * @param  {String}  sid - the session ID
   *
   * @return {Promise}
   */
  async connect (sid) {
    util.validate(['sid', 'a UUID', sid])

    const session = this.sessions.get(sid)

    if (!session) {
      throw new Error('Session not found')
    }

    let conn = this.conns.get(sid)

    if (conn) {
      throw new Error('Already connected')
    }

    conn = new WebSocket(`wss://${this.host}:${this.port}`, { ca: this.ca })

    await EventEmitter.once(conn, 'open')

    const msg = JSON.stringify({ id: decodeURIComponent(this.id), sid })

    conn.send(msg)

    const [{ data }] = await EventEmitter.once(conn, 'message')

    if (data !== 'OK') {
      throw new Error(data)
    }

    this.conns.set(sid, conn)

    conn
      .once('close', this.handleClose.bind(this, sid))
      .on('message', this.handleMessage.bind(this, session, sid))
  }

  /**
   * Disconnect from a session.
   *
   * @param  {String}  sid - the session ID
   */
  disconnect (sid) {
    util.validate(['sid', 'a UUID', sid])

    const session = this.sessions.get(sid)

    if (!session) {
      throw new Error('Session not found')
    }

    const conn = this.conns.get(sid)

    if (!conn) {
      throw new Error('Not connected')
    }

    conn.close()
  }

  /**
   * Encrypt a plaintext and send it to peer in session.
   *
   * @param  {String}           sid       - the session id
   * @param  {(Buffer|String)}  plaintext - the plaintext to encrypt and send
   */
  send (sid, plaintext) {
    util.validate(
      ['sid', 'a UUID', sid],
      ['plaintext', 'a buffer or string', plaintext]
    )

    const session = this.sessions.get(sid)

    if (!session) {
      throw new Error('Session not found')
    }

    const conn = this.conns.get(sid)
    let { header, payload } = session.encrypt(plaintext)
    header = header.toString('hex')
    payload = payload.toString('hex')
    const msg = JSON.stringify({ header, payload })

    conn.send(msg)
  }

  /**
   * Publish bundle to server.
   *
   * @return {Promise}
   */
  async publishBundle () {
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

    const pubKey = Buffer.from(this.pubKey).toString('hex')
    const pubSignPreKey = Buffer.from(this.pubSignPreKey).toString('hex')
    const preKeySig = Buffer.from(this.preKeySig).toString('hex')
    oneTimeKeys = oneTimeKeys.map(({ pubKey }) => pubKey.toString('hex'))

    const headers = { 'Content-Type': 'application/json' }
    const data = JSON.stringify({ pubKey, pubSignPreKey, preKeySig, oneTimeKeys })
    const resp = await this.request({ data, headers, method: 'PUT', path: '/bundle' })

    if (resp.statusCode !== 201) {
      throw new Error(`Code ${resp.statusCode}: ${resp.data}`)
    }

    return Buffer.from(this.pubKey)
  }

  /**
   * Fetch peer bundle from server and send initial message to establish session.
   *
   * @param  {Buffer}           peerKey   - the peer's public key
   * @param  {(Buffer|String)}  plaintext - the initial plaintext to encrypt and send
   *
   * @return {Promise}
   */
  async sendInitMessage (peerKey, plaintext) {
    util.validate(
      ['peerKey', 'a public key', peerKey],
      ['plaintext', 'a buffer or string', plaintext]
    )

    const id = Client.id(peerKey)
    const path = '/bundle/' + id
    let resp = await this.request({ path })

    if (resp.statusCode !== 200) {
      throw new Error(`Code ${resp.statusCode}: ${resp.data}`)
    }

    const bundle = JSON.parse(resp.data)
    let pubSignPreKey = Buffer.from(bundle.pubSignPreKey, 'hex')
    const preKeySig = Buffer.from(bundle.preKeySig, 'hex')
    const valid = axl.verify(peerKey, pubSignPreKey, preKeySig)

    if (!valid) {
      throw new Error('Invalid signature')
    }

    const ephemeral = util.genKeyPair()
    let oneTimeKey = Buffer.from(bundle.oneTimeKey, 'hex')

    const dhs = [
      nacl.scalarMult(this.privKey, pubSignPreKey),
      nacl.scalarMult(ephemeral.privKey, peerKey),
      nacl.scalarMult(ephemeral.privKey, pubSignPreKey),
      nacl.scalarMult(ephemeral.privKey, oneTimeKey)
    ]

    const ad = Buffer.concat([this.pubKey, peerKey])
    const ikm = Buffer.concat([Buffer.alloc(32, 0xFF), ...dhs])
    let okm = util.hkdf({ ikm, info: this.info, length: 96 })
    const secKeys = []

    for (let i = 0; i < 3; i++) {
      secKeys.push(okm.slice(0, 32))
      okm = okm.slice(32)
    }

    const session = new Session()

    session.init({ ad, info: this.info, keyPair: this, peerKey, secKeys })

    let { header, payload } = await session.encrypt(plaintext)

    const pubKey = Buffer.from(this.pubKey).toString('hex')
    const ephemeralKey = Buffer.from(ephemeral.pubKey).toString('hex')
    pubSignPreKey = pubSignPreKey.toString('hex')
    peerKey = Buffer.from(peerKey).toString('hex')
    oneTimeKey = oneTimeKey.toString('hex')
    header = header.toString('hex')
    payload = payload.toString('hex')

    const data = JSON.stringify({ pubKey, peerKey, pubSignPreKey, ephemeralKey, oneTimeKey, header, payload })
    const headers = { 'Content-Type': 'application/json' }
    resp = await this.request({ data, headers, method: 'POST', path: '/message' })

    if (resp.statusCode !== 201) {
      throw new Error(`Code ${resp.statusCode}: ${resp.data}`)
    }

    this.sessions.set(resp.data, session)

    return resp.data
  }

  /**
   * Receive initial message from server to establish session with peer.
   *
   * @param  {String}   sid - the session ID
   *
   * @return {Promise}
   */
  async recvInitMessage (sid) {
    util.validate(['sid', 'a UUID', sid])

    const resp = await this.request({ path: '/message/' + sid })

    if (resp.statusCode !== 200) {
      throw new Error(`Code ${resp.statusCode}: ${resp.data}`)
    }

    const msg = JSON.parse(resp.data)
    const pubKey = Buffer.from(msg.pubKey, 'hex')
    const pubSignPreKey = Buffer.from(msg.pubSignPreKey, 'hex')
    const ephemeralKey = Buffer.from(msg.ephemeralKey, 'hex')
    let oneTimeKey = Buffer.from(msg.oneTimeKey, 'hex')
    const header = Buffer.from(msg.header, 'hex')
    const payload = Buffer.from(msg.payload, 'hex')

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
    let okm = util.hkdf({ ikm, info: this.info, length: 96 })
    const secKeys = []

    for (let i = 0; i < 3; i++) {
      secKeys.push(okm.slice(0, 32))
      okm = okm.slice(32)
    }

    const session = new Session()

    session.init({ ad, info: this.info, keyPair: this, secKeys })
    this.sessions.set(sid, session)

    return session.decrypt({ header, payload })
  }

  handleClose (sid) {
    this.conns.delete(sid)
    this.sessions.delete(sid)

    /**
     * Emitted when session WebSocket closes.
     * @event Client#disconnected
     *
     * @type {String}
     */
    this.emit('disconnect', sid)
  }

  handleMessage (session, sid, msg) {
    try {
      msg = JSON.parse(msg)
    } catch {
      /**
       * @event Client#error
       *
       * @type {Error}
       */
      this.emit('error', new Error('Invalid message'))
      return
    }

    const header = Buffer.from(msg.header, 'hex')
    const payload = Buffer.from(msg.payload, 'hex')

    let plaintext

    try {
      plaintext = session.decrypt({ header, payload })
    } catch {
      this.emit('error', new Error('Decryption failed'))
      return
    }

    /**
     * Emitted when client receives message for a certain session.
     * @event Client#message
     *
     * @type     {Object}
     * @property {String} sid       - the session ID
     * @property {Buffer} plaintext - the plaintext message
     */
    this.emit('message', { sid, plaintext })
  }
}

module.exports = Client
