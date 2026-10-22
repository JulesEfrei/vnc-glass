# Support wayvnc's login through RSA-AES, not VeNCrypt

With `enable_auth=true`, wayvnc only offers encrypted security types: RSA-AES and VeNCrypt/TLS. RoyalVNCKit supports neither. We add RSA-AES to the copied package (#13), with AES-EAX framing around the stream after the handshake and the server's key trusted on first use per address and port. RSA comes from Apple's Security framework and the AES building blocks from CryptoSwift, so we write no new cipher code. VeNCrypt stays unsupported.

## Considered Options

- **VeNCrypt/TLS**: the crypto would come from the system's TLS, but the connection has to switch to TLS partway through, which `NWConnection` cannot do cleanly, and wayvnc's self-signed certificate needs its own trust flow. Unmerged upstream PR #40 is a reference if this changes.
- **Only `relax_encryption=true` (Apple DH, type 30)**: works with no new code, but protects the password with weak cryptography and asks the user to weaken their server.
- **No login (`enable_auth=false`) behind Tailscale**: still supported, but some users want the server to keep its own login.
