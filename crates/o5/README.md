# o5 Pluggable Transport Library

This is a spiritual successor to `obfs4` updating some of the more annoying / out of
date elements without worrying about being backward compatible.


⚠️  🚧 WARNING This crate is still under construction 🚧 ⚠️
- protocol under development
- interface subject to change at any time 
- Not production ready
  - do not rely on this for any security critical applications

## Differences from obfs4

- Frame / Packet / Message construction
  - In obfs4 a "frame" consists of a signle "packet", encoded using xsalsa20Poly1305.
  we use the same frame construction, but change a few key elements:
    - the concept of "packets" is now called "messages"
    - a frame can contain multiple messages
    - update from xsalsa20poly1305 -> chacha20poly1305
    - padding is given an explicit message type different than that of a payload message and uses the mesage length header field
      - (In obfs4 a frame that decodes to a payload packet type `\x00` with packet length 0 is asummed to all be padding)
      - move payload to message type `\x01`
      - padding takes message type `\x00`
    - (Maybe) add bidirectional heartbeat messages

- Handshake
  - x25519 key-exchange -> [X-Wing](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem#name-with-hpke-x25519kyber768dra) (ML-KEM + X25519) Hybrid Public Key Exchange
    - the overhead padding of the current obfs4 handshake (resulting in paket length in [4096:8192]) is mostly unused
    we exchange some of this unused padding for a kyber key to provide post-quantum security to the handshake.
    - [Kemeleon Encoding](https://docs.rs/kemeleon/latest/kemeleon/) for obfuscating ML-KEM public keys and ciphertext on the wire.
    - [Elligator2](https://docs.rs/curve25519-elligator2/latest/curve25519_elligator2/) for obfuscating X25519 public keys.
  - [PQ-Obfs handshake](https://eprint.iacr.org/2024/1086.pdf)
    - Adapted from the [NTor V3 handshake](https://spec.torproject.org/proposals/332-ntor-v3-with-extra-data.html)
  - Change mark and MAC from sha256-128 to sha3-256
  - Allow messages extra data to be sent with the handshake, encrypted under the key exchange public keys
    - the client can provide initial parameters during the handshake, knowing that they are not forward secure.
    - the server can provide messages with parameters / extensions in the handshake response (like prngseed)
    - This takes space out of the padding already used in the client handshake.
  - (Maybe) session tickets and resumption

### Goals
* Post Quantum Forward Secrecy - traffic captured today cannot be decrypted by a quantum computer tomorrow.
* Stick closer to Codec / Framed implementation for all packets (hadshake included)

### Features to keep
- once a session is established, unrecognized frame types are ignored

