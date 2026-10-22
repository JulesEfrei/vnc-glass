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
