#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Synchronization

/// A first-in, first-out queue that the send loop drains while the API and the receive loop fill it, so it locks.
final class Queue<T> {
	private let list = Mutex([T]())

	func enqueue(_ element: T) {
		list.withLock { $0.append(element) }
	}

	func dequeue() -> T? {
		list.withLock { $0.isEmpty ? nil : $0.removeFirst() }
	}

	func clear() {
		list.withLock { $0.removeAll() }
	}

	func peek() -> T? {
		list.withLock { $0.first }
	}

	var isEmpty: Bool {
		list.withLock { $0.isEmpty }
	}
}
