//
//  GeneratingBLEPayload.swift
//  ContinuityTests
//
//  Created by Alexander Heinrich on 05.09.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import XCTest
import CommonCrypto
#if swift(>=5.1)
import CryptoKit
#endif

class GeneratingBLEPayload: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testGenerateBLEPayload() {
        // The payload string will be any activity type that the user can do. This one is for editing a note
        let payloadString = ":com.apple.notes.activity.edit-note".lowercased()

        
        let expectedPayload = "<88085c34 2dc9ed>".hexadecimal!


        let payloadBytes = generateAdvertisementBytes(forString: payloadString)
        print("Payload bytes\n", payloadBytes.hexadecimal)
        
        XCTAssertEqual(payloadBytes, expectedPayload)
    }

    
    func testBLEPayloadClipboard() {
        // The payload string will be any activity type that the user can do. This one is for editing a note
        let payloadString = ":com.apple.continuitypasteboard".lowercased()
        let expectedPayload = "<a1072cb8 bf1d98>".hexadecimal!
        
 
        //Expected SHA512 hash
        //0x700008446060: a6 71 55 2d e6 eb 2b ba 25 41 59 30 14 54 32 74  �qU-��+�%AY0.T2t
        //0x700008446070: 5d a2 19 7b 12 84 c7 80 13 8f 0f 5d 58 52 0b c0  ]�.{..�....]XR.�
        //0x700008446080: 8e a2 67 3d 33 39 07 d0 05 da 3b 80 ef b2 3b e1  .�g=39.�.�;.�;�
        //0x700008446090: cc df 7d d1 ec f4 46 c4 e4 7c e9 e4 6e 96 1d 6e  ��}���F��|��n..n
        
        let payloadBytes = generateAdvertisementBytes(forString: payloadString)
        XCTAssertEqual(payloadBytes, expectedPayload)
    }
    
    func generateAdvertisementBytes(forString payloadString: String) -> Data {
        //According to the reverse engineering it's using a function in CoreServices.framework called LSCreateHashedBytesForAdvertisingFromString
        //This function uses the c string version of the payload and hashes it with SHA512. Then it takes only 7  bytes from the hash to represent the payload
        
        
        let payloadCString = payloadString.cString(using: .utf8)!
        //String length without the terminating 0 char
        let stringLength = payloadCString.count-1
        
        var shaHash = [UInt8](repeating: 0x00, count: Int(CC_SHA512_DIGEST_LENGTH))
        CC_SHA512(payloadCString, CC_LONG(stringLength), &shaHash)
        
        let shaHashData = Data(shaHash)
        print("Sha Hash \n", shaHashData.hexadecimal)
        
        
        let payloadBytes = shaHashData[shaHashData.startIndex...shaHashData.startIndex.advanced(by: 6)]
        print("Payload bytes\n", payloadBytes.hexadecimal)
        
        return payloadBytes
    }
 
    func testCompareHashes() {
        let payloadString = "com.apple.notes.activity.edit-note".lowercased()
        
        //According to the reverse engineering it's using a function in CoreServices.framework called LSCreateHashedBytesForAdvertisingFromString
        //This function uses the c string version of the payload and hashes it with SHA512. Then it takes only 7  bytes from the hash to represent the payload
        
        var payloadCString = payloadString.cString(using: .utf8)
        var shaHash_GivenLength = Array<UInt8>(repeating: 0x00, count: Int(CC_SHA512_DIGEST_LENGTH))
        var shaHash_ManualLength = Array<UInt8>(repeating: 0x00, count: 64)
        var shaHash_ExtraLength = Array<UInt8>(repeating: 0x00, count: 0x60)
        
        CC_SHA512(&payloadCString, CC_LONG(payloadCString!.count), &shaHash_GivenLength)
        
        CC_SHA512(&payloadCString, CC_LONG(payloadCString!.count), &shaHash_ManualLength)
        
        CC_SHA512(&payloadCString, CC_LONG(payloadCString!.count), &shaHash_ExtraLength)
        
        XCTAssertEqual(shaHash_GivenLength, shaHash_ManualLength)
        
        XCTAssertEqual(shaHash_GivenLength, Array(shaHash_ExtraLength[0...63]))
    }
    
    #if swift(>=5.1)
    func testDecryptWithGCM() throws {
        let keyData = "<9cdbb22f 8dfc0198 bbf9b31e 7d64438e 1755094b ad224d32 d897c634 e71ffb9c>".hexadecimal!
        let key = SymmetricKey(data: keyData)
        let counter = "57b1".hexadecimal!
        let tag = "0x70".hexadecimal!
        let data = "b97aad02 b573a397 d4fa".hexadecimal!
        
        //The counter builds the nonce
        let nonce = try AES.GCM.Nonce(data: counter)
        let aesSelaed = try AES.GCM.SealedBox(nonce: Nonce, ciphertext: data, tag: tag)
        let decrypted = AES.GCM.open(aesSelaed, using: key)
        
        
        
    }
    #endif

}
