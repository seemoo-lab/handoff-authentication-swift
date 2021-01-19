import XCTest


final class Handoff_SwiftTests: XCTestCase {

    override func setUp() {
        if (sodium_init() < 0) {
            fatalError("initialization failed")
        }
    }
    
    func testKeyExchange() {
        //This is a test which simulates a key exchange
        //1. We generate a keypair for both sides
        
        var ownSecretKey = Array<UInt8>(repeating: 0, count: Int(crypto_box_SECRETKEYBYTES))
        var ownPublicKey = Array<UInt8>(repeating: 0, count: Int(crypto_box_PUBLICKEYBYTES))
        //First generate 0x20 random  bytes like Apple does in PairingSessionExchange
        randombytes_buf(&ownSecretKey, Int(crypto_box_SECRETKEYBYTES))
        //Then use the curve without a base to derive a public key
        crypto_scalarmult_base(&ownPublicKey, &ownSecretKey)
        
        var peerSecretKey = Array<UInt8>(repeating: 0, count: Int(crypto_box_SECRETKEYBYTES))
        var peerPublicKey = Array<UInt8>(repeating: 0, count: Int(crypto_box_PUBLICKEYBYTES))
        //First generate 0x20 random  bytes like Apple does in PairingSessionExchange
        randombytes_buf(&peerSecretKey, Int(crypto_box_SECRETKEYBYTES))
        //Then use the curve without a base to derive a public key
        crypto_scalarmult_base(&peerPublicKey, &peerSecretKey)
        
        //2. We generate a shared secret by using the own secret key and the peer's public key
        var sharedSecret = Array<UInt8>(repeating: 0, count: Int(crypto_scalarmult_BYTES))
        //Use the own secret key and the peers public key for the shared secret generation
        let success = crypto_scalarmult_curve25519(&sharedSecret, &ownSecretKey, &peerPublicKey)
        
        XCTAssertEqual(success, 0)
        
        //3. We generate the same shared secret on the other side
        var peerSharedSecret = Array<UInt8>(repeating: 0, count: Int(crypto_scalarmult_BYTES))
        let peerSuccess = crypto_scalarmult_curve25519(&peerSharedSecret, &peerSecretKey, &ownPublicKey)
        
        XCTAssertEqual(peerSuccess, 0)
        
        //Compare both shared secrets
        XCTAssertEqual(peerSharedSecret, sharedSecret)
    }
    
    func testKeyExchangeCoreCrypto() throws {
        //This is a test which simulates a key exchange
        //1. We generate a keypair for both sides
        let hkdfSpec = KeyGeneration.HKDFInfo(info: "Pair-Verify-ECDH-Info", salt: "Pair-Verify-ECDH-Salt", keyLength: KeyGeneration.Constants.curveKeyLength)
        
        let ownKeys = try KeyGeneration.generateCurve25519RandomKeypair(usingHKDF: hkdfSpec)
        
        let peerKeys = try KeyGeneration.generateCurve25519RandomKeypair(usingHKDF: hkdfSpec)
        
        //2. Generate a shared secret with curve25519
        let sharedSecret = try KeyGeneration.curve25519(secretKey: ownKeys.secretKey, base: peerKeys.publicKey)
        let secretArray = Array(sharedSecret)
        
        let peerSharedSecret = try KeyGeneration.curve25519(secretKey: peerKeys.secretKey, base: ownKeys.publicKey)
        let peerSecretArray = Array(peerSharedSecret)
        
        //Compare the secrets
        XCTAssertEqual(sharedSecret, peerSharedSecret)
        XCTAssertEqual(secretArray, peerSecretArray)
    }
    
    
    func testHKDF() {
        let secretString =  "2d73a632cac0fea730fb11cfb96ed7327d6ce837b5560042a4fb6cbe692ea005"
        let secret = secretString.hexadecimal!
        
        let expectedKeyString = "7b 2c b8 da 5d 03 ae 7a 9c c8 3e 6d 2b 2e 9d 49 10 4b 28 94 2f e5 b0 63 67 16 15 42 23 07 2f 29".replacingOccurrences(of: " ", with: "")
        let expectedKey = expectedKeyString.hexadecimal!
        
        //Perform HKDF
        let salt = "Pair-Verify-Encrypt-Salt"
        let info = "Pair-Verify-Encrypt-Info"
        
        let hkdfKey = KeyGeneration.cryptoHKDF(input: secret, outLength: 32, salt: salt, info: info)
        
        XCTAssertEqual(hkdfKey, expectedKey)
    }
    
    //Fails when using Apple's ed curve keys
//    func testSigningDataWithLibsodium() {
//        //1. We load the signing keypair
//        let signingKeys = PairingDevice.current.signingKeys!
//        var secretKey = Array(signingKeys.edSecretKey)
//        var publicKey = Array(signingKeys.edPublicKey)
//
////        crypto_sign_keypair(&secretKey, &publicKey)
//
//        var generatedPubKey = Array<UInt8>(repeating: 0x00, count: Int(crypto_box_PUBLICKEYBYTES))
//        crypto_scalarmult_ed25519_base(&generatedPubKey, &secretKey)
//
//        let message = "This is a test message that should be signed"
//        let messageData = message.data(using: .utf8)
//        let messageArray = Array(messageData!)
//
//        //Sign the message
//        var signedMessage = Array<UInt8>(repeating: 0, count: Int(crypto_sign_BYTES) + messageArray.count)
//        var signedMessageLen: UInt64 = 0
//
//
//        let success = crypto_sign_ed25519(&signedMessage, &signedMessageLen, messageArray, UInt64(messageArray.count), &secretKey)
//        XCTAssertEqual(success, 0)
//
//        //Verify the signature
//        var unsignedMsg = Array<UInt8>(repeating: 0, count: Int(signedMessageLen) - Int(crypto_sign_BYTES))
//        var unsignedMsgLen: UInt64 = 0
//        let verified = crypto_sign_ed25519_open(&unsignedMsg, &unsignedMsgLen, signedMessage, signedMessageLen, &publicKey)
//        XCTAssertEqual(verified, 0)
//        XCTAssertEqual(unsignedMsg, messageArray)
//
//        let unsignedString = String(data: Data(unsignedMsg), encoding: .utf8)
//        XCTAssertEqual(unsignedString, message)
//    }
    
    
    func test_chacha20poly1305() throws {
        // Generate the decryptionKey
        let sharedSecret = try KeyGeneration.randomBytes(forSize: 0x20)
        
        let key = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
        
        //Encrypt the test message
        let testMessage = "This is a test message that should be encrypted"
        let testData = testMessage.data(using: .utf8)!
        // 12 byte nonce
        let nonce = "PV-Msg02-123".data(using: .ascii)!
        
        let encrypted = try Crypto.chacha20poly1305Encrypt(key: key, nonce: nonce, aad: nil, message: testData)
        
        //Append authTag at the end
        var encryptedData = encrypted.encrypted
        encryptedData.append(encrypted.authTag)
        
        
        let decrypted = try Crypto.chacha20poly1305Decrypt(key: key, nonce: nonce, aad: nil, encrypted: encryptedData)
        
        XCTAssertEqual(decrypted, testData)
        let decryptedString = String(data: decrypted, encoding: .utf8)
        XCTAssertEqual(decryptedString, testMessage)
    }
    
    func test_chacha20poly130564x64() throws {
        // Generate the decryptionKey
        let sharedSecret = try KeyGeneration.randomBytes(forSize: 0x20)
        
        let key = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
        
        //Encrypt the test message
        let testMessage = "This is a test message that should be encrypted"
        let testData = testMessage.data(using: .utf8)!
        let nonce = "PV-Msg02".data(using: .ascii)!
        
        var encrypted:  (encrypted: Data, authTag: Data)!
        do {
            encrypted = try Crypto.chachaPoly1305Encrypt64x64(key: key, nonce: nonce, aad: nil, message: testData)
        }catch {
//            log(error)
            XCTAssert(false, "Encrypting failed")
            return
        }
        
        XCTAssertNotEqual(encrypted.encrypted, testData)
        
        //Append authTag at the end
        var encryptedData = encrypted.encrypted
        encryptedData.append(encrypted.authTag)
        
        var decrypted: Data!
        do {
            decrypted = try Crypto.chachaPoly1305Decrypt64x64(key: key, nonce: nonce, aad: nil, encrypted: encryptedData)
        }catch {
            XCTAssert(false, "Decrypting failed")
            return 
        }
        
        
        XCTAssertEqual(decrypted, testData)
        let decryptedString = String(data: decrypted, encoding: .utf8)
        XCTAssertEqual(decryptedString, testMessage)
    }
    
    func testPairingSessionVerifyDecryption() throws {
        let encrypted = "c6078a53a05bb23ad8102abec622774d3a9589a6748c72ec9248ba0f081da1e87a4663787b6b34b85bb2aea1f4af803c96b6ae2553b0b58cebede36a969bc7ed7288474422896a14605483d88c65b521ff25604306".hexadecimal!
        let sharedSecret = "8503c60909332a3739696d87f42503ea573fab5a3a0f321a0ec2dd97d9cd9d57".hexadecimal!
        
        //2. Generate the decryptionKey
        let decryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")

        //3. Decrypt the data
        let nonce = "PV-Msg02".data(using: .ascii)!
        
        var decrypted: Data!
        do {
            decrypted = try Crypto.chachaPoly1305Decrypt64x64(key: decryptionKey, nonce: nonce, aad: nil, encrypted: encrypted)
        }catch {
            XCTAssert(false, "Decryption failed")
            return
        }
        
        let tlv = try TLV8Box.deserialize(fromData: decrypted)
        
        let signature = tlv.getValue(forType: PairingSession.PairingTLV.signature)
        XCTAssertNotNil(signature)
        
        if let signature = signature {
            print("Received signature \(signature.hexadecimal)")
        }
        
        let appFlags = tlv.getValue(forType: PairingSession.PairingTLV.appFlags)
        XCTAssertNotNil(appFlags)
        if let appFlags = appFlags {
            print("Received App flags \(appFlags.first!)")
        }
        
    }
    
    func testSignatureVerification() throws {
        let currentPublicKey = "64eb0731f50dcc61038145de356a7e8471569e8987eee59db61fcfdb0e469913".hexadecimal!
        let peerPublicKey = "56bf61d799b2ce01861af5b89014fd0dc86bfe34822d1e09cf402f5dc5757220".hexadecimal!
        let signature = "f17fdad0b0beca0e35b53ab80d71b28434781db05b7c6bdb7652d83e217b06a500598ac1c52107d9ca01480e0fa34343c9b677d66caef338eb96cb173361b007".hexadecimal!
        
        //Construct the signed data
        var message = peerPublicKey
        message.append(currentPublicKey)
        
        //Verify that the signed data matches the signature
        let verified = Signing.verifyEd25519Signature(signature: signature, message: message, pk: PairingDevice.current.signingKeys.edPublicKey)
        
        XCTAssertTrue(verified)
    }
    
    func testcalculateHeaderOfPacket() throws {
        let header = ContinuityPacket.Header(firstByte: .encryptedData, bodySize: 100)
        XCTAssertEqual(Array<UInt8>(header.data), Array<UInt8>([0x08, 0x00, 0x00, 0x74]))
        XCTAssert(header.expectedDataSize() == 116)
    }

//    static var allTests = [
//        ("testExample", testExample),
//    ]
}
