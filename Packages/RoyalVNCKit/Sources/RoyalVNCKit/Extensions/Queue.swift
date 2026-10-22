#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Synchronization

/// A first-in, first-out queue that the send loop drains while the API and the receive loop fill it, so it locks.
final class Queue<T> {
	private let list = Mutex([T]())
	/// The send loop waiting in `waitForElement`, resumed by the next `enqueue`.
	private let waiter = Mutex<CheckedContinuation<Void, Never>?>(nil)

	func enqueue(_ element: T) {
		list.withLock { $0.append(element) }
		waiter.withLock { $0.take() }?.resume()
	}

	/// Returns once an element is queued, or after `timeout` so the caller can check its own state. One caller at a
	/// time; it may also return early, so the caller checks the queue again.
	func waitForElement(timeout: Duration) async {
		let timer = Task { [self] in
			try? await Task.sleep(for: timeout)
			waiter.withLock { $0.take() }?.resume()
		}
		defer { timer.cancel() }

		await withCheckedContinuation { continuation in
			// Checked under the waiter lock, so an enqueue between the check and the wait still resumes it.
			let resumeNow = waiter.withLock { waiter in
				guard isEmpty else { return true }
				waiter = continuation
				return false
			}
			if resumeNow { continuation.resume() }
		}
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
