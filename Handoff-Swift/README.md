# Handoff-Swift

This is a sample implementation that allows creating a *companion link* connection with another device. This implementation will complete the full Pairing Session handshake and exchange relevant keys. A first implementation of the *Universal Clipboard* protocol has been started. The implementation works most reliable with macOS 10.15 or earlier. Apple has changed parts of the protocol in iOS 13.x and macOS 10.15.x. Even though the first 3 steps of the authentication handshake are still supported on macOS 11 (Big Sur) and iOS 14, the last step keeps failing. 

## Usage 
The project consits of a single runnable binary that search with Bonjour for any devices that support Handoff in close proximity. Then it will automatically try to authenticate with the first device it discovered. 
It does not have an UI as it is only an implementation of the reverse engineered Continuity authentication protocol.

## Implementation 
The main implementation of the authentication protocol is part of the `PairingSession` class. The authentication session can be initialized by using the `connect(to:)` function. The rest of the authentication will run automatically. 
The `Handoff` class contains an implmenentation of a `BonjourBrowser` that searches for supported devices and starts a pairing session automatically. 
