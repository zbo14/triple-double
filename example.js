'use strict'

const { once } = require('events')
const fs = require('fs')
const path = require('path')
const { Client, Server } = require('./lib')

const fixtures = path.join(__dirname, 'test', 'fixtures')
const cert = fs.readFileSync(path.join(fixtures, 'cert.pem'))
const key = fs.readFileSync(path.join(fixtures, 'key.pem'))
const ca = cert
const host = 'localhost'
const port = 8888

const alice = new Client({ ca, host, port })
const bob = new Client({ ca, host, port })
const server = new Server({ cert, key })

const run = async () => {
  await server.start(port, host)

  console.log('Started server')

  const pubKey = await alice.publishBundle()

  console.log('Alice published bundle')

  const plaintext = 'initial plaintext'
  const sid = await bob.sendInitMessage(pubKey, plaintext)

  console.log('Bob sent initial message')

  await alice.recvInitMessage(sid)

  console.log('Alice received initial message')

  await Promise.all([
    alice.connect(sid),
    bob.connect(sid)
  ])

  console.log('Alice and bob connected')

  alice.on('message', msg => {
    if (msg.sid === sid) {
      console.log('Bob says: ' + msg.plaintext)
    }
  })

  bob.on('message', msg => {
    if (msg.sid === sid) {
      console.log('Alice says: ' + msg.plaintext)
    }
  })

  const promise = Promise.all([
    once(alice, 'disconnect'),
    once(bob, 'disconnect')
  ])

  alice.send(sid, 'Hello "bob"')
  bob.send(sid, 'Hello "alice"')

  setTimeout(() => {
    alice.disconnect(sid)
    bob.disconnect(sid)
  }, 1e3)

  await promise

  server.stop()

  console.log('Stopped server')
}

run().catch(console.error)
