//
//  SigningTests.swift
//  ContinuityTests
//
//  Created by Alexander Heinrich on 04.07.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import XCTest

class SigningTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        
        if (sodium_init() < 0) {
            fatalError("initialization failed")
        }
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }


    func testSignWithCoreCrypto() {
        
        //1. We load the signing keypair
        let signingKeys = PairingDevice.current.signingKeys
        
        //        crypto_sign_keypair(&secretKey, &publicKey)
        
        let message = "This is a test message that should be signed"
        let messageData = message.data(using: .utf8)
        
        let signature = Signing.signWithEd25519(message: messageData!, pk: signingKeys.edPublicKey, sk: signingKeys.edSecretKey)
        XCTAssertNotNil(signature)
        XCTAssertGreaterThan(signature.count, 0)
        XCTAssertEqual(signature.count, Int(Signing.signatureLength))
        
        let verified = Signing.verifyEd25519Signature(signature: signature, message: messageData!, pk: signingKeys.edPublicKey)
        XCTAssertEqual(verified, true)
    }
    
    func testSignWithGeneratedKeys() throws {
        //1.Generate some random signing keys
        
        let signingKeys = KeyGeneration.generateEd25519SigningKeys()
        
        //Sign a message
        let message = "This is a test message that should be signed"
        let messageData = message.data(using: .utf8)
        
        let signature = Signing.signWithEd25519(message: messageData!, pk: signingKeys.edPublicKey, sk: signingKeys.edSecretKey)
        
        XCTAssertNotNil(signature)
        XCTAssertGreaterThan(signature.count, 0)
        XCTAssertEqual(signature.count, Int(Signing.signatureLength))
        
        let verified = Signing.verifyEd25519Signature(signature: signature, message: messageData!, pk: signingKeys.edPublicKey)
        
        XCTAssertEqual(verified, true)
    }
}
