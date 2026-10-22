import AppKit
import SessionCore
import SwiftUI

/// The settings that apply to every Connection, kept in UserDefaults and read by each Session window.
struct SettingsView: View {
    @AppStorage("UnlockShortcut") private var unlockShortcut = UnlockShortcut.default
    @AppStorage("LocksInFullScreen") private var locksInFullScreen = true
    @AppStorage("IsClipboardSyncEnabled") private var isClipboardSyncEnabled = true

    var body: some View {
        Form {
            LabeledContent("Unlock Shortcut") {
                UnlockShortcutRecorder(shortcut: $unlockShortcut)
            }
            Toggle("Lock automatically in full screen", isOn: $locksInFullScreen)
            Toggle("Sync clipboard with the remote computer", isOn: $isClipboardSyncEnabled)
        }
        .formStyle(.grouped)
        .frame(width: 420)
    }
}

/// Records a new Unlock Shortcut: the modifier keys held together, taken once they are all released. Any other key,
/// or a single modifier, cancels.
private struct UnlockShortcutRecorder: View {
    @Binding var shortcut: UnlockShortcut
    @State private var monitor: Any?
    /// Every modifier held since recording started.
    @State private var pressed: Set<KeyCode> = []

    var body: some View {
        Button(monitor == nil ? shortcut.description : "Press modifier keys…") {
            if monitor == nil { start() } else { stop() }
        }
        .help("Click, then press and release the modifier keys that turn Lock Mode on and off.")
        .onDisappear(perform: stop)
    }

    private func start() {
        pressed = []
        monitor = NSEvent.addLocalMonitorForEvents(matching: [.flagsChanged, .keyDown]) { event in
            guard event.type == .flagsChanged else {
                stop()
                return nil
            }
            let held = modifierKeys.values.filter { event.modifierFlags.rawValue & $0.1 != 0 }.map { KeyCode(hidUsage: $0.0) }
            pressed.formUnion(held)
            if held.isEmpty {
                if let recorded = UnlockShortcut(keys: pressed) { shortcut = recorded }
                stop()
            }
            return nil
        }
    }

    private func stop() {
        if let monitor { NSEvent.removeMonitor(monitor) }
        monitor = nil
    }
}
