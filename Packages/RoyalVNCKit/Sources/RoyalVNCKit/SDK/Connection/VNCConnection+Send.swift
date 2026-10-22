#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Client to Server Messages
extension VNCConnection {
	func startSendLoop() {
        logger.logDebug("Starting send loop")

		sendTask = Task(priority: taskPriority) {
			while !state.disconnectRequested,
                  connection.isReady {
				do {
					try await send()
				} catch {
					handleBreakingError(error)
				}
			}
		}
	}

	/// Queued like every other client message: the send loop must be the stream's only writer, or RSA-AES frames go out
	/// of order and the server hangs up.
	func sendFramebufferUpdateRequest() {
		guard let framebuffer,
              !state.areContinuousUpdatesEnabled else {
            return
        }
        
		let incremental = state.incrementalUpdatesEnabled

		let fullFramebufferRegion = VNCRegion(location: .zero,
											  size: framebuffer.size)

		// Request next update
		enqueueClientToServerMessage(VNCProtocol.FramebufferUpdateRequest(incremental: incremental,
																		  xPosition: fullFramebufferRegion.location.x,
																		  yPosition: fullFramebufferRegion.location.y,
																		  width: fullFramebufferRegion.size.width,
																		  height: fullFramebufferRegion.size.height))

		if !incremental {
			state.incrementalUpdatesEnabled = true
		}
	}

	func sendEnableContinuousUpdates() {
		guard let framebuffer,
              state.areContinuousUpdatesSupported,
              !state.areContinuousUpdatesEnabled else {
            return
        }

		let fullFramebufferRegion = VNCRegion(location: .zero,
											  size: framebuffer.size)

		enqueueClientToServerMessage(VNCProtocol.EnableContinuousUpdates(enable: true,
																		 xPosition: fullFramebufferRegion.x,
																		 yPosition: fullFramebufferRegion.y,
																		 width: fullFramebufferRegion.width,
																		 height: fullFramebufferRegion.height))

		state.areContinuousUpdatesEnabled = true
	}
}

private extension VNCConnection {
	func send() async throws {
		guard !state.disconnectRequested,
              connection.isReady,
			  let message = clientToServerMessageQueue.dequeue() else {
			if state.disconnectWhenQueueIsEmpty { return beginDisconnecting() }
			try await Task.sleep(seconds: 0.01)

			return
		}

		try await sendMessage(message)
	}

	func sendMessage(_ message: VNCSendableMessage) async throws {
		try await message.send(connection: connection)
	}
}
