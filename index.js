'use strict'

const fs = require('fs')
const path = require('path')
const Server = require('./lib/server')

const privDir = path.join(__dirname, 'private')
const cert = fs.readFileSync(path.join(privDir, 'cert.pem'))
const key = fs.readFileSync(path.join(privDir, 'key.pem'))

const server = new Server({ cert, key })
const host = process.env.host || '0.0.0.0'
const port = +process.env.port || 8888

server
  .on('error', console.error)
  .start({ host, port })
  .then(() => console.log(`Server listening on "${host}:${port}"`))
  .catch(err => {
    console.error(err)
    process.exit(1)
  })
