# Vendor RoyalVNCKit as a local package instead of depending on it

RoyalVNCKit (MIT, Swift, macOS + iOS) is archived upstream and lacks features our wayvnc target supports: Extended Clipboard (UTF-8), QEMU Extended Key Event (scancodes) and client SetDesktopSize. We copy its source into this repo as a local Swift package and add those messages ourselves, rather than wrapping the GPL LibVNCClient or living with Latin-1 clipboard and keysym-only input.

## Considered Options

- **RoyalVNCKit via SwiftPM, unmodified**: no upstream fixes ever, missing features stay missing.
- **LibVNCClient**: more complete, but GPL would bind the whole app and we would write our own framebuffer views.
