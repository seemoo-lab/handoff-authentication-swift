//
//  CommunicationDecryptionTests.swift
//  ContinuityTests
//
//  Created by Alexander Heinrich on 25.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import XCTest

//Global variables

var serverPairingIdentity: PairingIdentity?

class CommunicationDecryptionTests: XCTestCase {
    
    /// Pairing verify initialization packet. Always done by client
    var m1: ContinuityPacket!
    /// Pairing verify reply with encrypted data and signed public keys. Answer from "server"
    var m2: ContinuityPacket!
    /// Pairing verify by client. Contains encrypted signature and HomeKit Pairing Identity.
    var m3: ContinuityPacket!
    /// Pairing verify complete. Answer from server when everything is successful
    var m4: ContinuityPacket!
    /// Used to decrypt messages
    var sharedSecret: Data!
    
    var dataPackets: [ContinuityPacket]!
    
    var serverPublicKey: Data?
    var clientPublicKey: Data?
    
    override func setUp()  {
        
        do {
        //Store all pairing session packets in variables
        let m1Data = "0500002fe1435f706491280601010320efa42d3c2b7cf705239f0e5973e7f44efbd6c408e1db6f72a894a655d1750903190101".hexadecimal!
        self.m1 = try ContinuityPacket(data: m1Data)
        
        let m2Data = "06000083e1435f7064917c0555cfb0390914ec087d384ecb5ffbcd6901bbf0e73c45d8e179b49b602eabc8fd3dd428a7a078c95e2775c834c7f10813b23fecc7830244bf61d4b0bec1be213ee1161315ad5978bdbcf222613afe13bcf0e77ee0a7f606010203205d0ecde5ae85317902640fe983912e13427bcf6f400ee1fbdff31c82e52f4c74".hexadecimal!
        self.m2 = try ContinuityPacket(data: m2Data)
        
        let m3Data = "0600005ee1435f706491570552af5c988698513b4a8969dd7542c62eef279e87d9a2a404b48a565788e8975ab842a63259c86d23607727763d6b3e241c4036d1027d42c1f51a3f9ff76c11ac2205837c6c474b0821f4521ded6000765bb691060103".hexadecimal!
        self.m3 = try ContinuityPacket(data: m3Data)
        
        let m4Data = "06000009e1435f706473060104".hexadecimal!
        self.m4 = try ContinuityPacket(data: m4Data)
            
        let tlvM1 = try m1.pairingTLV()
        clientPublicKey = tlvM1.getValue(forType: PairingSession.PairingTLV.publicKey)
        
        let tlvM2 = try m2.pairingTLV()
        serverPublicKey = tlvM2.getValue(forType: PairingSession.PairingTLV.publicKey)
            
        self.dataPackets = try CommunicationDecryptionTests.getDataPackets()
            
        }catch {
            fatalError("Initialization failed")
        }
        
        self.sharedSecret = "0c 5c 0c 73 21 43 0c 90 68 6d b2 b7 1e 66 0d bc cc 2e 77 d5 7a c4 5a f1 52 a7 f8 9f 08 95 2c 4a".replacingOccurrences(of: " ", with: "").hexadecimal!
    }
    

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    
    func testM1() throws {
        let tlvM1 = try m1.pairingTLV()
        
        let publicKey = tlvM1.getValue(forType: PairingSession.PairingTLV.publicKey)
        XCTAssertNotNil(publicKey, "Public Key not found")
        clientPublicKey = publicKey!
        
        let state = tlvM1.getValue(forType: PairingSession.PairingTLV.state)
        XCTAssertNotNil(state, "State not found")
        XCTAssertEqual(0x1, Array(state!)[0])
        let appFlags = tlvM1.getValue(forType: PairingSession.PairingTLV.appFlags)
        XCTAssertNotNil(appFlags)
    }
    
    /// This test will handle all necessary operations on an M2 packet. It will decrypt it's content and verify the signature
    func testM2() throws {
        //Parse the packet
        let tlvM2 = try m2.pairingTLV()
        
        let publicKey = tlvM2.getValue(forType: PairingSession.PairingTLV.publicKey)
        XCTAssertNotNil(publicKey, "Public Key not found")
        serverPublicKey = publicKey!
        
        // Generate the decryptionKey
        let decryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
        
        //Get encrypted data
        guard let encrypted = tlvM2.getValue(forType: PairingSession.PairingTLV.encryptedData)
            else {throw PairingError.parsingFailed}
        
        //Decrypt
        let nonce = "PV-Msg02".data(using: .ascii)!
        let decrypted = try Crypto.chachaPoly1305Decrypt64x64(key: decryptionKey, nonce: nonce, aad: nil, encrypted: encrypted)
        
        //Verify decrypted Data
        //Should be a TLV
        let tlv = try TLV8Box.deserialize(fromData: decrypted)
        let signature = tlv.getValue(forType: PairingSession.PairingTLV.signature)
        let appFlags =  tlv.getValue(forType: PairingSession.PairingTLV.appFlags)
        
        XCTAssertNotNil(signature)
        XCTAssertNotNil(appFlags)
        
        // Verify the signature to ensure the partner is valid
        do {
            let pairingIdentity = try PairingVerifier(publicKey: clientPublicKey!, peerPublicKey: serverPublicKey!).verifySignatureFromPeer(signature!)
            
            serverPairingIdentity = pairingIdentity
        }catch let error  {
            print(error)
            XCTAssert(false, "Failed verifying signature")
        }
    
        //If completed until here! Good to go
    }
    
    func testM3() throws {
        let tlvM3 = try m3.pairingTLV()
        
        // Generate the decryptionKey
        let decryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
        
        //Get the encrypted data
        guard let encrypted = tlvM3.getValue(forType: PairingSession.PairingTLV.encryptedData)
            else {throw PairingError.parsingFailed}
        
        //Decrypt it
        let nonce = "PV-Msg03".data(using: .ascii)!
        let decrypted = try Crypto.chachaPoly1305Decrypt64x64(key: decryptionKey, nonce: nonce, aad: nil, encrypted: encrypted)
        
        //Get the decrypted TLV
        let tlv = try TLV8Box.deserialize(fromData: decrypted)
        let signature = tlv.getValue(forType: PairingSession.PairingTLV.signature)
//        let identityIdData =  tlv.getValue(forType: PairingSession.PairingTLV.identityId)
        XCTAssertNotNil(signature)

        do {
            let pairingIdentity = try PairingVerifier(publicKey: serverPublicKey!, peerPublicKey: clientPublicKey!).verifySignatureFromPeer(signature!)
        }catch let error  {
            print(error)
            XCTAssert(false, "Failed verifying signature")
        }
        
    }
    
    func testM4() throws {
        let tlvM4 = try m4.pairingTLV()
        
        let state = tlvM4.getValue(forType: PairingSession.PairingTLV.state)
        XCTAssertNotNil(state, "State not found")
        XCTAssertEqual(0x4, Array(state!)[0])
        
    }
    
    func testGetEncryptionKeys() throws {
        let secret = "b7 d9 fc 80 e7 f5 6d 59 1a 10 66 0c ea 5f 91 ee 7f f8 43 82 ab a9 68 5c be 01 6b 80 0e 05 f9 61".replacingOccurrences(of: " ", with: "").hexadecimal!
        
       let encryptionKey = KeyGeneration.cryptoHKDF(input: secret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "", info: "ServerEncrypt-main")
        
        let expectedEncryptionKey = "f9 31 8f 99 40 93 d3 2d 6a db dd ec 5c 8a b1 ae 58 0e 49 43 a6 15 a0 18 38 cc 95 de 28 6f 45 6f".replacingOccurrences(of: " ", with: "").hexadecimal!
        
        XCTAssertEqual(encryptionKey, expectedEncryptionKey)
        
    }
    
    func testGetClientEncryptionKeys() {
        let secret = "19 ec 12 c1 c8 b7 f1 8e df 58 6a dc ee ef c3 86 66 c5 bf 50 d6 ac 79 e0 a3 6f 4d c0 06 6a 67 27".replacingOccurrences(of: " ", with: "").hexadecimal!
        
        let encryptionKey = KeyGeneration.cryptoHKDF(input: secret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "", info: "ClientEncrypt-main")
        
         let expectedEncryptionKey = "ca 19 2f 45 53 5f cc 48 62 55 e7 98 19 5f a3 60 3f d2 9f bc 9f 8c 99 5a 60 08 ef c0 d6 db 52 2d".replacingOccurrences(of: " ", with: "").hexadecimal!
        
        XCTAssertEqual(encryptionKey, expectedEncryptionKey)
    }
    
    func testDecrypt() {
        let secret = "17 7c d1 31 04 b6 3a 08 aa 91 e7 f7 94 71 35 6b 7d 43 ce 71 59 6e b9 32 5a d9 37 3c bf e0 6f 5f".replacingOccurrences(of: " ", with: "").hexadecimal!
        
        let encryptionKeyGem = KeyGeneration.cryptoHKDF(input: secret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "", info: "ServerEncrypt-main")
        
        let header: Data = "08 00 00 a5".replacingOccurrences(of: " ", with: "").hexadecimal!
        let encryptedData = "f9cd20fb 6d029f96 ef8d9859 20a46d9c dc933d4d d3b5baa4 e6b86591 ab419f8b d6ca3e0d 5e33f03b c7812055 73015539 dc92be21 991d9419 08264a37 dc4a4e53 f5388bc0 54d2804a 5eb35500 b3459fef c342a0ae 7362d2fa caa2f31d 5daf3d71 030691f3 3ca7cdf8 a0250568 57ea9e67 23d34b85 1c08c014 ce73f8ea ad2f2f40 64ce1dde 53a779e0 f2455f1e ffcbb5ff 1f69453a 386026fc f7007593 897d086c 6cc302db a7".replacingOccurrences(of: " ", with: "").hexadecimal!
        
        let encryptionKey = "97 02 69 97 11 7a ff d0 2e bd 29 1a a7 5e 97 8c f8 40 95 32 32 80 ad 7c a6 84 2b 7b 84 08 ba f9".replacingOccurrences(of: " ", with: "").hexadecimal!
        
        XCTAssertEqual(encryptionKeyGem, encryptionKey)
        
        var clientNonce: Int = 1
        
        var clientNonceData = Data(bytes: &clientNonce, count: MemoryLayout.size(ofValue: clientNonce))
        if clientNonceData.count < 12 {
            let count = 12 - clientNonceData.count
            clientNonceData.append(Data(repeating: 0x00, count: count))
        }
        
        let aad = Data(header)
        
        let decrypted = try? Crypto.chacha20poly1305Decrypt(key: encryptionKey, nonce: clientNonceData, aad: aad, encrypted: encryptedData)
        
        XCTAssertNotNil(decrypted)
    }
    
    
    func test_decryptCommunication() throws {
        var clientNonce: Int = 0
        var serverNonce: Int = 0
        
        let keyServerEncryptionMain = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "", info: "ServerEncrypt-main")
        
        let keyClientEncryptionMain = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "", info: "ClientEncrypt-main")
        
        
        
        try dataPackets.forEach { (packet) in
            //Try decrypting the packet
            var serverNonceData = Data(bytes: &serverNonce, count: MemoryLayout.size(ofValue: serverNonce))
            if serverNonceData.count < 12 {
                let count = 12 - serverNonceData.count
                serverNonceData.append(Data(repeating: 0x00, count: count))
            }
            var clientNonceData = Data(bytes: &clientNonce, count: MemoryLayout.size(ofValue: clientNonce))
            if clientNonceData.count < 12 {
                let count = 12 - clientNonceData.count
                clientNonceData.append(Data(repeating: 0x00, count: count))
            }
            
            let aad = packet.header.data
            
            var decrypted = try? Crypto.chacha20poly1305Decrypt(key: keyServerEncryptionMain, nonce: serverNonceData, aad: aad, encrypted: packet.body)
            
            if let d = decrypted {
                serverNonce += 1
                //Opack decode the decrypted data
                try self.handleDecryptedData(d)
                return
            }
            
            decrypted = try? Crypto.chacha20poly1305Decrypt(key: keyClientEncryptionMain, nonce: clientNonceData, aad: aad, encrypted: packet.body)
            
            if let d = decrypted {
                //Opack decode the decrypted data
                clientNonce += 1
                try self.handleDecryptedData(d)
                return
            }
            
            XCTAssertNotNil(decrypted)
        }
        
    }
    
    func test_decryptCommunication_2() throws {
        var clientDecryptor = HandoffCryptor(withSharedSecret: sharedSecret, andMode: .client)
        var serverDecryptor = HandoffCryptor(withSharedSecret: sharedSecret, andMode: .server)
        
        try dataPackets.forEach { (packet) in
 
            
            
            var decrypted = try?  serverDecryptor.decrypt(continuityPacket: packet)
            
            if let d = decrypted {
                //Opack decode the decrypted data
                try self.handleDecryptedData(d)
                return
            }
            
            decrypted = try? clientDecryptor.decrypt(continuityPacket: packet)
            
            if let d = decrypted {
                //Opack decode the decrypted data
                try self.handleDecryptedData(d)
                return
            }
            
            XCTAssertNotNil(decrypted)
        }
        
    }
    
    func test_handlePackets() throws {
        var clientHandler = HandoffHandler(withSharedSecret: sharedSecret, andMode: .client)
        var serverHandler = HandoffHandler(withSharedSecret: sharedSecret, andMode: .server)
        
        var filenum = 1
        
        try dataPackets.forEach { (packet) in
            var dict: [AnyHashable: Any]!
            do {
                dict = try clientHandler.handleDecrypt(continuityPacket: packet)
                
            }catch {
                
            }
            
            do {
                dict = try serverHandler.handleDecrypt(continuityPacket: packet)
            }catch {
                
            }
            
            XCTAssertNotNil(dict)
            
            if let messageContent = dict["_c"] {
                if let contentDict = messageContent as? [AnyHashable: Any] {
                    if let payloadData = contentDict["rActPayload"] as? Data {
                        //Write to file
                        let url = FileManager.default.homeDirectoryForCurrentUser
                            .appendingPathComponent("tmp")
                            .appendingPathComponent("handoff-msg1-packet-\(filenum).plist")
                        filenum += 1
                        
                        try payloadData.write(to: url)
                        
                        let unarchiver = try NSKeyedUnarchiver(forReadingFrom: payloadData)
                        let pasteboardInfoWrapper = unarchiver.decodeObject(of: UASharedPasteboardInfoWrapper.self, forKey: NSKeyedArchiveRootObjectKey)
                        
                        print(pasteboardInfoWrapper)
                        XCTAssertNotNil(pasteboardInfoWrapper)
                    }
                }
            }
        }
    }
    
    func test_uasharedpasteboard_archiving() throws {
//        let typeInfo = UASharedPasteboardTypeInfo()
        
    }
    
    func handleDecryptedData(_ decrypted: Data) throws  {
        let decoded  = try OPACKCoding.decode(fromData: decrypted)
        
        print(decoded)
    }
    
    static func getDataPackets() throws -> [ContinuityPacket] {
        let packetArray = ["9eb269d843828ae590be12bb86dd602c8621010d0640fe8000000000000088e590fffebe12bbfe800000000000009cb269fffed84382cebbc07ef96e9c5564b1bb6980180801899000000101080a23f5460b6e4a1d99080000e9db0610e10e42d995dc0f6ff4f7be8587deb44cb820a770a634f5487646b8b5a596d6f3ef90022753d274f2775a6e302f3f2c98c305087e9d0ac61516c130381b21c10c5738d6e3f0fe6832a4ca55628e5a47574c78f60a6103ea12282f104639e9b36c9e7dd6735f15f0973b1be7b3c93eb601478dd2526a90599568409151243e0c42a7d1e56dc1be1cb54d8c2cb034c6b0d63283109820dc37873fb54c649704ca663f7f8158dd284017f73bd644c9e4d81c27af651bb300a1deecc6b9405544d04f95a4dda826cce3f66bdd3995eac5b07c122fdd0e6f4b38bc07a2d73c5a7c15a738855ce82ae4","8ae590be12bb9eb269d8438286dd6028060300f90640fe800000000000009cb269fffed84382fe8000000000000088e590fffebe12bbc07ecebb64b1bb69f96e9d4280180800132e00000101080a6e4a1da123f5460b080000d5f4478b71eb543a26cd59105f351651142d1cd9d6a26752e58d4af956b39f53260793a9f2502c0f15c4899569b986f0db9a065639733beaa2ce2e3d9b0ffe72ffffc03f4d0145f2e24f869eb3735652b26f8c49f38fd76494cbce25fcbf5a61c2219bf1e98beb7ee9f5ff8ba32436f4c275c1ba28903c00c8971268c00cd42923eaf681f5d89925f5c3b661d8b8f0ce81f1a52b2c8de57ddbb3dbadf4fcd08a51bcb5366822a024f3e910e20cb528e302d0e3814e91301c711a61d50c71d61c24cd920cdf2c4cceab5a105ec88d0dd8da09a971ab13", "9eb269d843828ae590be12bb86dd602c862100cd0640fe8000000000000088e590fffebe12bbfe800000000000009cb269fffed84382cebbc07ef96e9d4264b1bc4280180800881100000101080a23f5460d6e4a1da1080000a9081dcf5c65dadc69dd2277077342d64283ad572cd9ab0f46f3c46a16b42bed3eed16291843582ecf9c55839dc1ad10a6ab174eb2d5230a631502c6dcba1a93b00bcee0f233535fb0509b538fceb65d9f8760d4b05c33ed61525c96c764d10e42b90d320553228ccc4ee6b401a8cd38a376907d988cac92aa1a0634cc9bcbc035acc8657861a7bf9d98fa11bc4ed26f938811d2ba3cdbe53bf48b49a51088660d7d043e4297c1e3d272", "8ae590be12bb9eb269d8438286dd6028060305a40640fe800000000000009cb269fffed84382fe8000000000000088e590fffebe12bbc07ecebb64b1bc42f96e9def80100800251800000101080a6e4a1da623f5460d08000a517d363f36e588c67d85ce86ef716b6f9bff9bc90d4a37635e1be5f595e23bf669af5d829b57d1ab9a26a8fa60346f278910238a40d0d146a5779d115193c08f697a0e96be4b193ad3da239d1f7a75ab469eca487d350538e6c0340f32ca2fa5124a4d387985e66b6c9e4e0916149dacf8c8864c5094c593e9b3d33207110d04b0d600c7dbee52727db84b493a6b419c4d61fb68f8a680e01605a65ab63777fff417e95eccf47962cb50cef62700926579d71af45633cd0370e58836f9c7e43f737de271e6b8d4352d57db3c2e6316a8e6639401b011cab8cb8909e278fa9e638470a166bf81ce1c068e09f04ce393cecb56e820ed67b29a9e84f47bc8476c54a3cef2303cc50036aab5b6bea038ba87d2559f2d3fdc26e44673d539301784d001e68ded9de26af25c8a32abec48b4b14d9dacd714b55455910a22144e420e885ec8186d9bdb20c9799b476169ba2c0de9a645ba0dd1e28fcd6d7697bd59c11bd9f5afe4189c641a9778b3b0bbbd8ea7a846c1cf3dd75d5c27828245039577511617afc03fed46c88dca993e87999f28f6bc34ac281d6f874828d9ecd4aaad62847294d14744866ec6e22a1964039a2ee68f21511a26df7467ec48557a6c794c82c8ecb3c48fce4bd985c52872198e269ee0ca5a49f3d52b33d8714503f58c7edec5f176e4f79d58b8e421b0d3734a8403015935a83eaad0e67ebfe553a8f6b2a1e10f542bee6121d0c758e3a144ec7947130642665c9834f4a3e427692f663b2d215a573c74a82b48d7c1d146e5432d2dd92bad6029a959e775ea1d12ce3e5e34c111e8fdf9f82d6cb679c4814dc9fe3808bd8647ec2794e50a6f9e2883fa7e09337b541eb8b0d165d567d7b536c1531f33cf4a7c5f01f50db1fe475bff6eec94d0cd18ec04bdc80b3b05c2bfcf2efd1b31e329223760db41f79bec2af548ad77895444190232f7714332050e89f017eaad031117c2057bb049edbe115ac2c82b914ce711f8cfedcebaa1086bc0393cce520e04d80692cd46662e61e8bae089fec088eba9e1203b3486d5ac256d98e1c3277ce1bdec7823099eef02ba9de2e078d40b6958c69cf738924a394529570f3fa27f2a38628d94555f69f68a1bb9283792dbbb18746fc5607dfe27abbf96c4cbbe98db69cde50e622a8d8bfa2055d13b0ea7820e1dc22919825e7653441eee160d322fa278651d1e4ff87d4750d5955ed580c808e11b764f16508150721062fe3a3d4c60360f54fdad4bff2b866ab41a7d451598180c62189311d11d6b03c14e767cd707f36ace4bd0858b73bca617358ed79fa745ed530f5db3dd93b5cb0fb4dddff0f9124953f3617b5be901eec6363ca3a65ce1a855981196c6a2dda0242742c145da291206ef4394433f49fd9365d877ea4c96d98ee0c98b36b85feb74c2e3bb0a57b83d8e02bc2c41b6ddf56319adb1f0ab8eb09cb9181c6c73030df0abecfd7b03a109e72a49ca4b2b0371d8476aec522c8c1050d2779529791ca0f93f0b17bcc6f4b40e1746e87bce2f2c3c5bc49826ed9c8e9a93627d3eff9b05454bec30dde83d0acbd88e987aa41f9a9943514d455991a49305099c4eaa138cd9d66006b0e592ef8d28bb9a74502fc1f947e227e3a8bc5da6fa692e545a7e590bca65d76a013b4a8a0198ba2a611b4e5122ff861efd6ea68807bc80251e788f369b81258ace9f6a655c36967ad44dd00a64faeacdd398891b6fb28e7b14dfa33b9a3583bfe0c7a65b167e8855e062002417f933feba5bc5a9e7d35095dc5322db48717dc631990670a5570639a5ceadbbc823697208a80f799cffc5eb64ed24c48445ec49447e9825496d59e9e1ae68ab2ca89e25c265747a631809e39a89c41b7a644cc6797530cd14d657fdb6cce43c763e594a226f25bb751e515122692624239d582cf0935e382eb31501d81ea8fc87fd51c74d21dbce33bee3244b71cd3af00dc84f463dc56184f8d9cf5444f4c91a" + "2d6cfc04c541d169f9b11a908a1543c8244a0db9b6705d492c101ffd68dc06cff13a1d74c6e2135dd33fdfe1a36d615f5d0c533730cba8d2c71a15d22d4b274279b5400018466fcfeee3b17ea9cdce3a24c0fb1980ae23cbef0da7bcf2e3172de34a94f4685760ee9903635715412673b5d2b45e4771390943f73952882cb38fe6477eb496c0c9fc186d54c127c44243490c2889b364088a3b9c4829431b9e3f8b19e99ae94a51c225a0078d6a41746f6593a4c78fbf79d0571a9de56fb0889f24ef4c1ded3ca16acfb6d87828375d49fdbad62703e5f6fa7e61de12ace648fd1f57928c491de7339f024586b201ab6a88a5a6a2b430cac49b6e6252f6617df2c8bc44c426dba4a42fc1e2ab713da52365a849d82849275fa3574725387bb64337127832451ec177bd2458ee88c1b173c34aa48d6fe83e0985d790d18f681f0e53fdff81b7d9d66c6b3b24003ad68457b8108fd20456bbf02be86f2fdbb4479244bae02c4de45fcc6e2bc85192d836404b551258041f0a695b38057b0a886bf7792e8cb7fa6c13e61b65f0309fa2939eadc51ae1a8b6233f03b7bd4ccf975c54dd23e1f16aa173efaec3b0471ec4b05f84c6a9d1eab02027f6cfb492d86a19abc4a62b041f4e276e87e2bfd15b71fd4e8e74eb7afb13085ecd62b7e2b4cb619d54e6687c0eac7f07c6fd8650981bc58fc966b30ef964415985b85eb05801625bfa4168694177d69eeddb5dd79308541e975b4d41095d9c066fe1b9c2dd270e5c3427a5d64e09c8c54fa2150f9c7ec3b6ef69fa1ee40d9e66bcfc8f1c994a34d505a65e4c7710020fa182830b7ba68f659ff94c2cc205338a11c6364ef9229a6938a9c7230773d552220a35383778acacee52ebbddbf490baad5b30c955fb220d3839b4af2585a07ea3000a096e6b669f6b9d3193ff6c7b3e3e17005459b772b214a81648afc6fd9d8ca187c5494e1e956c4a0303f9c14a6b2508e820327e93039ab54f2cebba373f7e34fc53c82f161ea2e02800c5fbc80d9a85d655ce06470ed2d73cedf0810abf17e70589d1a764b998c613fb7f4b0695c49d2f3015818e692d7b0e2b9433aa82712c3214c63d9972e044f3d75efa7d184f4ecc3eda04c6963884095df279662b7c5c56649f62e5efc763a6df88ffe2f6eda8e9b105edbc4426c77b07c73e656ac8475ec0d42bfa4307dcbb883fcf74b0dfd9bcb440bbd788574f07ba0f1f549ce73d74079b37b0fc4710134d3cefccce120f164ab3e3b289b8c8e1ae8f0b1cf1d180b64c4c69aaa4ffb0526c70161f520d40a594933b2f5a251969ece2cb392c8b6d97f7aff1d937a9d8ab48c1840ae39b33d67591ec0bc49e1f2da1defcd8698501e2b82d6668c7a796a7e74ce831ff3f5e9c07b53b5734d6d1a42517a216ec3d7e152fa564e5da6ceff71265c6cd90c5d0604f8824a28bce3e1b68909ff04125794999a63741e4fbe9ab545a8cc56fbcd29ec166b39a14a2dd3a24e733bc6c5b6ef9a2d56dff7db1d1d127b5d27891785e89b4f0eb4877b5f725f4bdfb57df090ac4997f14b42275f6176feaf53a7d56c9ca008485f1138c8e7e5217340f1b12aa58face1ded71ae0e517192577692bb9cf7be1e00a5965fbc818670b24872b2a2f780e3bfa05fb41d9e3dcb67049aaa82dbd81c57049b0226340ed7b0465cf23dc2acf6222d6af9b1766a509272508b05376ef92aaa20f38db791effe0007e9074b01b5944cd97f"
        ]
        
        //Create continuity packets
        let continuityPackets = try packetArray.compactMap({ (packetString) -> ContinuityPacket? in
            //Split to only get the data
            let seperator = "08000"
            let components = packetString.components(separatedBy: seperator)
            guard  components.count == 2
                else {print("Multiple components detected"); return nil}
            
            let packetData = (seperator + components[1])
            let packet = try ContinuityPacket(data: packetData.hexadecimal!)
            return packet
        })
        
        return continuityPackets
    }

}
