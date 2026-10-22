import Testing
@testable import SessionCore

struct UnlockShortcutTests {
    @Test func survivesItsStoredForm() throws {
        let shortcut = try #require(UnlockShortcut(keys: [rightCmd, leftShift]))
        #expect(UnlockShortcut(rawValue: shortcut.rawValue) == shortcut)
    }

    @Test(arguments: ["", "224", "224,4", "224,x", "224,300"])
    func aStoredFormWithFewerThanTwoKeysOrKeysOtherThanModifiersIsRejected(rawValue: String) {
        #expect(UnlockShortcut(rawValue: rawValue) == nil)
    }

    @Test func isNamedLikeTheMacNamesModifiers() {
        #expect(UnlockShortcut.default.description == "left ⌃⌥")
        #expect(UnlockShortcut(keys: [rightCmd, leftShift])?.description == "left ⇧ right ⌘")
    }
}

private let leftShift = KeyCode(hidUsage: 0xE1)
private let rightCmd = KeyCode(hidUsage: 0xE7)
