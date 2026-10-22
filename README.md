# VNC Glass

A VNC viewer for macOS 26 with keyboard capture designed for Linux desktops. See `GLOSSARY.md` and `docs/adr/`.

## Layout

- `App/`: the macOS SwiftUI app, a thin AppKit edge over the Session core.
- `Packages/SessionCore`: the platform-agnostic Session core, plus `FakeRFBServer`, the in-process RFB server tests run against.
- `Packages/RoyalVNCKit`: vendored RoyalVNCKit (ADR-0002, see its `VENDORED.md`).

## Build

```sh
xcodegen generate        # writes VNCGlass.xcodeproj from project.yml
open VNCGlass.xcodeproj
```

Tests: `swift test --package-path Packages/SessionCore`.
