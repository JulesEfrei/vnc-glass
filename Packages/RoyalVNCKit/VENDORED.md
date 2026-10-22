# Vendored RoyalVNCKit

Copied from https://github.com/royalapplications/royalvnc (archived upstream) at
commit `090b96eddeee183e9fec293c5cd881d302a4349d` (1.1.0-16-g090b96e), see ADR-0002.
Licensed MIT, see `LICENSE`.

Taken: `Sources/RoyalVNCKit`, `Sources/RoyalVNCKitC`, `Sources/d3des`, `Sources/Z`.
Left out: the demos, language bindings, and the bundled zlib and stb_image (Windows/Linux only).

Changes from upstream:

- `Package.swift`: Apple platforms only (macOS 26, iOS 26), SwiftPM's default library type instead of a dynamic one, no library evolution,
  and CryptoSwift from its main repository instead of Royal Apps' fork (whose only changes are for
  Linux FoundationEssentials).
- RSA-AES and RSA-AES-256 security types (#13, ADR-0003): `RSAAESAuthentication`, `RSAAESFrameCipher`, and
  `RFBStream`, which wraps the network connection and encrypts both directions after the key exchange. The delegate
  gains `connection(_:shouldTrustServerKey:completion:)`, `VNCAuthenticationType` gains `.rsaAES`, and the C SDK
  refuses unknown server keys. A `RoyalVNCKitTests` target holds the cipher's fixed vectors.
- Tight security (16) is no longer chosen when offered: it was never implemented, so a server offering only it now
  fails as an unsupported security type (#3).
- d3des keeps its key schedule in a global, so `VNCDESEncryption.d3desLock` serializes every DES use; two Sessions
  logging in at once could otherwise encrypt with each other's password (#3).
- ARD: DH keys with a leading zero byte are padded to the key length instead of failing the login (about 1 in 128, #3).
- QEMU Extended Key Event (#4): the client announces pseudo-encoding -258 and, once the server confirms it, sends
  keys given with `keyDown(_:scancode:)`/`keyUp(_:scancode:)` as client message 255 with their XT scancode.
  `disconnect()` while connected now lets the send queue drain first, so key releases queued just before it reach the
  server (wayvnc #461).
- Clipboard (#6): with clipboard redirection off, ServerCutText goes to the new delegate method
  `connection(_:didReceiveClipboardText:)` instead of being dropped, and `sendClipboardText(_:)` sends ClientCutText.
  ClientCutText replaces characters Latin-1 lacks with `?` instead of sending an empty clipboard. The C SDK drops
  the server's clipboard when redirection is off.
- Extended Clipboard (#7): the client announces pseudo-encoding 0xC0A1E5CE and answers the server's caps with its
  own (text only, every change as a notify). `ExtendedClipboard` replaces the unfinished `ExtendedServerCutText`.
  Once the server's caps take text, `sendClipboardText(_:)` notifies and provides on request in UTF-8, re-notifying
  text sent as Latin-1 before the caps arrived; a server notify is answered with a request and its provide goes to
  the delegate. The clipboard monitor (redirection on) goes through `sendClipboardText(_:)` too. Messages over 20 MiB
  end the connection; provided text that inflates past it is dropped
  (`ZlibStream.decompressedData(compressedData:maximumLength:)`). `ProtocolError.unexpectedExtendedServerCutTextAction`
  is gone with the parser that threw it.
- The send queue locks: the API, the receive loop (clipboard replies) and the send loop all touch it from different
  threads, which upstream's plain array did not survive.
- Display Sizing (#8): `setDesktopSize(width:height:)` sends SetDesktopSize (client message 251) for one screen at the
  origin, keeping the id of the server's first screen. A request made before the server's first ExtendedDesktopSize
  rectangle is held until it arrives, and never sent to servers without one. `ExtendedDesktopSizeEncoding` reports that
  screen id to the connection.
