# triple-double

Create end-to-end encrypted WebSocket channels!

This package implements secret negotation via Extended Triple Diffie-Hellman (X3DH), allowing two peers to establish a WebSocket channel encrypted end-to-end with the [Double Ratchet Algorithm](https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm) and [header encryption](https://signal.org/docs/specifications/doubleratchet/#double-ratchet-with-header-encryption).

**WARNING:** this library has NOT received a formal security audit, use at your own risk.

## Install

`npm i triple-double`

## Usage

### Server

#### Generate TLS certificate

`npm run cert`

This generates a private key and self-signed certificate and writes them to `private/`.

**Note:** the client will need the certificate to connect to the server.

#### Start server

`[host=] [port=] npm start`

### Client

#### Example

The following code snippets assume top-level `async/await` for readability purposes.

A secure, out-of-band channel is needed to communicate public keys and session IDs between peers.

##### Alice publishes bundle

Alice only has to perform this step if:

* She hasn't published her bundle yet
* She runs out of one-time prekeys
* She wants to publish a new signed prekey

We'll assume she hasn't published her bundle yet.

See [here](https://signal.org/docs/specifications/x3dh/#publishing-keys) for more details.

```js
// Alice's code
const fs = require('fs')
const { Client } = require('triple-double')

const alice = new Client()
const ca = fs.readFileSync('/path/to/cert')

const pubKey = await alice.publishBundle({
  host: '1.2.3.4',
  port: 8888,
  ca
})

// Send public key to Bob out-of-band
```

##### Bob sends initial message

See [here](https://signal.org/docs/specifications/x3dh/#sending-the-initial-message) for more details.

```js
// Bob's code
const fs = require('fs')
const { Client } = require('triple-double')

const bob = new Client()
const ca = fs.readFileSync('/path/to/cert')

const sid = await bob.sendInitMessage({
  host:     '1.2.3.4',
  port:      8888,
  peerKey:   Buffer.from(/* alice's public key */),
  plaintext: 'initial plaintext',
  info:      Buffer.from('some info'),
  ca
})

// Send session ID to alice out-of-band
```

##### Alice receives initial message

See [here](https://signal.org/docs/specifications/x3dh/#receiving-the-initial-message) for more details.

```js
// Alice's code continued
const plaintext = await alice.recvInitMessage({
  host: '1.2.3.4',
  port: 8888,
  sid:  '<session ID from Bob>',
  info: Buffer.from('some info'),
  ca
})
```

##### Connect

At this point, the peers can establish a secure WebSocket channel.

This operation won't complete until *both* peers are connected.

```js
// Alice's code continued
await alice.connect({
  host: '1.2.3.4',
  port: 8888,
  sid:  '<session ID>',
  ca
})
```

```js
// Bob's code continued
await bob.connect({
  host: '1.2.3.4',
  port: 8888,
  sid:  '<session ID>',
  ca
})
```

##### Send/receive messages

After connecting, the peers can send messages to each other!

These messages are encrypted with Double Ratchet (including header encryption).

```js
// Alice's code continued
alice.on('message', ({ sid, plaintext }) => {
  if (sid === '<session ID>') {
    // handle Bob's plaintext
  }
})

alice.send({ plaintext: 'hello "bob"', sid: '<session ID>' })
```

```js
// Bob's code continued
bob.on('message', ({ sid, plaintext }) => {
  if (sid === '<session ID>') {
    // handle Alice's plaintext
  }
})

bob.send({ plaintext: 'hello "alice"', sid: '<session ID>' })
```

Alice and Bob can establish secure channels to other peers, if they so choose.

## Docs

`npm run doc`

This generates the documentation and writes it to `out/`.

Then you can open `out/index.html` in your browser.

## Test

`npm test`

## Lint

`npm run lint`

## Contributing

Go for it! Whether it's code cleanup, a bugfix, or feature request, your input is seriously appreciated.

Unsure where to start? Take a look at the code or [open an issue](https://github.com/zbo14/triple-double/issues/new).

## References
* [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
* [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
* [The XEdDSA and VXEdDSA Signature Schemes](https://signal.org/docs/specifications/xeddsa/)
