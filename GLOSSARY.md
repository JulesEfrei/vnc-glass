# VNC Glass

A VNC viewer for macOS (later iPadOS) for controlling a remote computer, with keyboard capture designed for Linux desktops.

## Language

**Connection**:
A saved remote computer the user can connect to: its address, credentials, Keyboard Profile and Display Sizing.
_Avoid_: Host, server, bookmark

**Session**:
One live link to a Connection, shown in its own window.
_Avoid_: Connection (when meaning the live link), tab

**Lock Mode**:
A Session state in which every keystroke goes to the remote computer and none act on the local Mac. The user enters it on purpose and it stays on until the Unlock Shortcut.
_Avoid_: Capture mode, focus mode, grab

**Paused**:
The state of a locked Session whose window is not focused: keystrokes act on the Mac until the window is focused again, when Lock Mode resumes by itself.
_Avoid_: Suspended, unlocked

**Reconnecting**:
The state of a Session whose link dropped without the user asking, while it retries on its own for about 30 seconds over the last frame. Lock Mode is off and stays off once it is back.
_Avoid_: Retrying, offline

**Unlock Shortcut**:
The one key combination that is never forwarded to the remote computer; it toggles Lock Mode on and off.
_Avoid_: Escape shortcut, super shortcut, hotkey

**Keyboard Profile**:
The rule set for translating local modifier keys to remote ones, chosen per Connection (for example Cmd as Super, or Cmd as Ctrl).
_Avoid_: Keymap, layout, conversion

**Display Sizing**:
A Connection's choice between Scale to Fit (the remote resolution never changes) and Match Window (the remote resizes to the Session window).
_Avoid_: Resolution mode, zoom
