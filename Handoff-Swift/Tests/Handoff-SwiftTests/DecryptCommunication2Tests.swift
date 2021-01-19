//
//  CommunicationDecryptionTests.swift
//  ContinuityTests
//
//  Created by Alexander Heinrich on 25.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import XCTest

//Global variables



class DecryptCommunication2Tests: XCTestCase {
    
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
            let packets = try DecryptCommunication2Tests.packets()

            self.m1 = packets["M1"] as? ContinuityPacket
            
            self.m2 = packets["M2"] as? ContinuityPacket
            
            self.m3 = packets["M3"] as? ContinuityPacket
            
            self.m4 = packets["M4"] as? ContinuityPacket
            
            let tlvM1 = try m1.pairingTLV()
            clientPublicKey = tlvM1.getValue(forType: PairingSession.PairingTLV.publicKey)
            
            let tlvM2 = try m2.pairingTLV()
            serverPublicKey = tlvM2.getValue(forType: PairingSession.PairingTLV.publicKey)
            
            self.dataPackets = packets["Data"] as? [ContinuityPacket]
            
        }catch {
            fatalError("Initialization failed")
        }
        
        self.sharedSecret = "82 91 93 f1 21 93 e6 25 34 87 17 49 b4 b6 eb b3 d8 e7 bd 31 48 89 b2 f5 7f dc d5 ff ee 4a 98 46".replacingOccurrences(of: " ", with: "").hexadecimal!
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

    
    func test_decryptCommunication() throws {
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
                        .appendingPathComponent("handoff-msg2-packet-\(filenum).plist")
                        filenum += 1
                        
                        try payloadData.write(to: url)
                        
                        //Convert to class
                        let unarchiver = try NSKeyedUnarchiver(forReadingFrom: payloadData)
                        let pasteboardInfoWrapper = unarchiver.decodeObject(of: UASharedPasteboardInfoWrapper.self, forKey: NSKeyedArchiveRootObjectKey)
                        
                        print(pasteboardInfoWrapper)
                        XCTAssertNotNil(pasteboardInfoWrapper)
                        
                        
                        
                        if let extraData = pasteboardInfoWrapper?.extraData,
                            pasteboardInfoWrapper?.extraDataType == 2 {
                                
                            //Extra data is
                                
                            print(String(data: extraData, encoding: .ascii)!)
                            
                            let url = FileManager.default.homeDirectoryForCurrentUser
                                .appendingPathComponent("tmp")
                                .appendingPathComponent("handoff-copied-content.plist")
                            try extraData.write(to: url)
                            
                            let extraDict = try PropertyListSerialization.propertyList(from: extraData, options: [], format: nil)
                            print(extraDict)
                        }
                    }
                }
            }
        }
    }
    
    
    
    func handleDecryptedData(_ decrypted: Data) throws  {
        let decoded  = try OPACKCoding.decode(fromData: decrypted)
        print(decoded)
    }
    
    static func parse(tcpHex: String) throws -> ContinuityPacket {
        let regex = try NSRegularExpression(pattern: "0[1-8]00", options: [])
        
        let start = 150
        let match = regex.firstMatch(in: tcpHex, options: [], range: NSRange(location: start, length: tcpHex.count - start))
        
        if let range = match?.range,
            range.location != NSNotFound {
            //Found the beginning of the packet
            let from = tcpHex.index(tcpHex.startIndex, offsetBy: range.location)
            let packetHex = String(tcpHex[from...])
            let packetData = packetHex.hexadecimal!
            
            return try ContinuityPacket(data: packetData)
        }
        
        throw NSError(domain: "Regex Not found", code: -1, userInfo: nil)
    }
    
    static func packets() throws -> [String: Any] {
        let rawPackets = [
            "M1": "9eb269d843828ae590be12bb86dd60267d6800530640fe8000000000000088e590fffebe12bbfe800000000000009cb269fffed84382cec2c07fddb651c2b2d47d1380180803363a00000101080a23f54a9f6e4a22130500002fe1435f706491280601010320ae22e1cd45bf207d35814ce5e1aca915c42c8119740292c670179085cf83c91e190101",
            "M2": "8ae590be12bb9eb269d8438286dd602f829700a70640fe800000000000009cb269fffed84382fe8000000000000088e590fffebe12bbc07fcec2b2d47d13ddb651f58018080369cd00000101080a6e4a222923f54a9f06000083e1435f7064917c05552509616b3da44e793a994248fe68b966b4691d4b91d66c0d806a4adbc2d8d3eb6b986863eeba3510294ea23b83aa6ab90263f02d773c2a29423657ebb999431e02b860c5bd8abd3a95ec4d86590b07ba47a428c74406010203203a9c45f871e5047d03af6332267285769cc8045d75654b2d87f92d64af9d4239",
            "M3": "9eb269d843828ae590be12bb86dd60267d6800820640fe8000000000000088e590fffebe12bbfe800000000000009cb269fffed84382cec2c07fddb651f5b2d47d9a80180801524d00000101080a23f54aaf6e4a22290600005ee1435f706491570552300824f3fb9b6d73977b89f93fee54c96c73a42180ec8c3b953d07ff7cdef4e3b502ea0f368e841e3c265b9fa9371ac3290182d40745a8d20b6bc0be0e0181195d0ccf5a26908002182d4094981c63273ac2060103",
            "M4": "8ae590be12bb9eb269d8438286dd602f8297002d0640fe800000000000009cb269fffed84382fe8000000000000088e590fffebe12bbc07fcec2b2d47d9addb6525780180801591f00000101080a6e4a223a23f54aaf06000009e1435f706473060104",
            "Data": [
                "9eb269d843828ae590be12bb86dd60267d6801090640fe8000000000000088e590fffebe12bbfe800000000000009cb269fffed84382cec2c07fddb65257b2d47da780180801897000000101080a23f54ab86e4a223a080000e567d09842e9bc00630de12ef515c141a6fff0a1fee1291633ec5a3535511a1600f433d6f2b270b0ae581604812e82030e4468c82865dddfa48b49fba1571ff00c85239104e1089a7db45f9f15c98eeb56707c9310bb570b692903e17d5cf3a91b53c364216e598a04484586f650dadfb5a03a05dd55fd741a9e2fa34f503d17b182a481655109e7f8b6a27dc729d487839f1101205e77bb94f4f251a19ea266f05f5f43867279dfeddd7910caa2b30c3b55f95c46a939ca14923ad909b316900e55f9f5a6db5042257739600570b95671037f2ed7e36cd05e8291441dfbf3e23a434de8fd71",
                "8ae590be12bb9eb269d8438286dd602f829700f50640fe800000000000009cb269fffed84382fe8000000000000088e590fffebe12bbc07fcec2b2d47da7ddb6534080180800b7af00000101080a6e4a224123f54ab8080000d1621a399339f04072490d15a44e7d98a208e766d8c33529a5dc182fa30379c29ac48de3fb8211e2f1befec21bf4b1c49a211c2cf560b0faa98cfcf23923a89d6374c6cf06fc42fe1f452cd62051f9a5b5a051a7e4e013b47c69fac2600283b181cccec50a8d084ec5366d759dea4692d43d01e546d3f301c17d236ecd0d6b685598c906afb24a08a2c73ad99f9ebdc7c44854776ad185e7062a20f1be5faf6b27eeb4fc98faf16a3d0eab3b4cf905b6e2c65090c371391bc68307aaa6076a06d899dc05e6de689f3eddd8a50651ab422c32",
                "9eb269d843828ae590be12bb86dd60267d6800ca0640fe8000000000000088e590fffebe12bbfe800000000000009cb269fffed84382cec2c07fddb65340b2d47e7c8018080075ad00000101080a23f54aba6e4a2241080000a62ebe3c6776d2d022d8b36ba3602e255b47ca84e945107fa75af6d77a827fe22088d512193af931341915853a32d0f5608cc75d950ac97ffdb803d7bf408cd21ee61a6e3c609b15cf01f568d69a618051f8f6f174f31f4201cbcbb4388ea2605b206412ee09045fb7cf9dc841d0a1e1b759cac8d0d32003f1a6d1c38ff57e72a7f57ad0376cad64065afd390760bdfc286cb1c7cf69e6511a1dc5f59764c85492f9528624af8e",
                "8ae590be12bb9eb269d8438286dd602f829705a40640fe800000000000009cb269fffed84382fe8000000000000088e590fffebe12bbc07fcec2b2d47e7cddb653ea80100800e91000000101080a6e4a225723f54aba080015dae9c19f3aa833037f12975180ede2944b2bf113b6cf57cfef07209fb667661db43555ad0cb8695892b00b854951651578a2dd0250c63a5bdd5a93d0b0fcada69f60a179ea4017871039161268bc552b21806367641a621dd3e1c7221b6ef4fdce7ded97bbe022278b8ea81567b464465d77c14b03146a6ad172f87a1ab82b2eb12addf0f5151bfecaae55717249fe321019d9de6c8c17fadfbd0c0b42ae7c9bbb9a1ec9614457878bcae6e7f0f3e8231557a810810d58040750b5d215a800c9ce90408a920ee3218379c5e662ad9fbcf4933d94c2de4dcc071c4c93a1ef32ac7c72dd3190990fad4d25b90b48412eb9212dcae2fe057302cc24b3496f7a9cad7f9e633c7d3e8fc91afb8bb0ff71d26cb5f9cc83ffede43c98cbefccad1ec22d1374b83274394d3f0b410b3c492ce6421c0620bcd2f56b8b374349c91b2b56d56f75c67213ebf7810d123ee863631362a0f8215f8b8fa60be5a41e073c3afd2c161b786006ff9cd54759bcdbf20be90e5653ed762dcafce62a5632a98b8309a125d2758e8e26ae5ae8c5516f9df55eafe88ac370fc3d603ce168598038537041b0ad91f6b5e62608a638900612d7e8d6fec41d6647cf824dba7177176ef33cd8d867c3b56dc639c2fda892a7bd03cdc83559b55fa6bdad0ff0ec7f3f2743500a65c07929cdc007242e5462c020cb07e4518ab0a81b336c9b53366f5ee103e8b92a57d9299a89f80ee19adb91ccf3e841062ca00149cc988172432b6759a5b2079167f26f94abb67279b639cea88efc2d8d32ce238668343295e9c25c158e4733f2fc7da298220300bc0e70a4f1a5b34d312dfb6d9d6296f20e7fc46e8599445885eabc41785a4e29261d89c2bb24596d0c0ae99a83c6d51f65ce2dff7ff6747079adc0a0e5502524e30b193c3e0e169113c6dc492046dc42a81681c202ade3c3cd985f0978356daf58bb36f4c175f1edc69bc86c74e70d053c8d02d9226e638dc86bcaacf880c0194b8e8f714b22c6618122b08c1924a6577e26588e1be3faf9e8f43965a3e97f5dcbea653a0d6261a9ebaa6507349aeb2a68078c8dcf04997d28981600e09608f3646c06907daaa931d1aabf06bbab19d3e1b569f4a170d8a56ad61b11de3d0946e61d4afcdf76103d403bce893dceab7c047a149f9fffa81ab1604c0ad4142904db3b206361b105bb92d7d25622eb82c07570e4703e7bde8b191c38459e69cac03905b462926ca4ff81ffefe9817be793d8c2f5dba5bde03ee7e1f7b99746abb6f3674f8f467f06a6903f7356f76f5f4285c887e39c8709af5c630402a2cfe4210b4dbbe88d26f7e5afd779dfaa581be0fac515f512a9d0f0bd16c4d414f4d1763bdb824e0edea10d1804149fe083022da1bf7ec7658efa597fb732ba165ce086ee8b5d0e58177c4ae84b12336de592342e572b9eba55bbc136fad7d3515ef972d5395051d25e08d5dccb7c60cf889c965eb92f3ffd87d179438ef9eb444e77953de26963d70e18bc21f8d3e161f8edb3d3d795f721442b903b7fe2d2ea4487f98036da86ea13fdb5d987acb9d00543247e60c638ce4bc428a3597f84911e449ed6da91a9e73eee8fbb806d7ab98e65b120a9ce24b3adeb79b447f49f8efe60cfc802956a8c8d8eef518740c7917010772ee8d6451d5e6b068d42175431a8d6c95fc9c41e0e9bf93b6ae26ede91dfea2306ca70b898addecaab371e66d2cae7a661532112db0eeca8d33a24da953122640165de56baba951d780abfcdce038161857f96aa0ba0b3eb7795e95b9c7bc625c939d398da668dced2372d3ce9f30908a51f635627bb3d11ea8f8111a604cd15c059b1d52b464a36b96a3955d68fe75d96977be30b3c8a53a36cf58e85edee1c1e8cf855c076a7a268af484bf1ba9a66df8d42c5b7e23c0ac55a8cdfc6bf54a3bd3c0fb54b399e62a147461ac1a6505050cedc1a089a7aeb04de148b93cdb463817be128a0f51cc6df"
                +
                "6cf87829a1a16ad73dc7a46ac12641910731008c2ad3eb60b7e5b6efcb2150c0f8207b0148b1162a50b17b266e09e26a0ff89a66736aa8fedbfcda69c7155719d9944ce5e468a33a1c74c6b36593c5c65bff13d8ea18c9ab201d78955aab3b48945e818943f8c6c9e8b119b853b099eede57ad3972797c83cbe8d06b72c1dcdcb02a9f37a18c794d6f95755d9964f085edf572140bb3fb2eeabcc35b5aefd7c54faa18dd627436c7d320dfe1674b2bc3d344024e75b51278ed2d673c0ba510d16ba70383490a2682bda063cac525e47b1c0dc5d1b24c31dfecddec943b0c6b8f6efa43d6b29a6a5f749b87d7f0bc591af37496946a4c9a8de741b557d40b417b83dc6f08e1dec4ca33504e31c554f80bd79a945663b0c259f558c12d9b9e3db192ac85ea963c097d10fcc79678db644e82db4d7f4fc29b633661de223b9f44710d4daf2a1f774890a3dd872cb0aec401ba808a9c4c28807f0abd2c966657161f256e991049e83face315fae01c9e898b94ec447b45b5f09b89f3e6a9e872e90d3c86e3f798fa5c6cffaf8a67af8ff563e9ce95f1d58398036e00c5c46915d4c18e78e4417fc66c55dbd272cfc0545ebf6976ceb1872268916b78c52301308471cfe8fb58033dea23656c2d872659c66f0bcabf584293d22bcf53beff66550a7d37ec4e27fdb8e8248b0f867c9b154cc9113fb700f882285408994f8e9cdd55f60a53b9846e32ea4f0a6145bcb3945df0b99dfc48c369db02c30e67fd8b50620ad5c5a6081b390215ed08961c17eb5a6d366873be9cc621ac88442162224e1e1da4d6f3347b8e92dc9dbfd148a7be365711970df8673aeb6d825e8933b49df8d3010cdf8f3b0f98714e66272b9c2c4a922e36bff48f1a2f2afc5270a230b77653a744f5f1f0de70cd801e4724590d8be107fac3f5d23865673894cf9970613be510094fbcca68ba5fb75c35571fbac522e64e56840e6d22678682d4dab95d1cbad1395000ec36a458c8fc3b1efa03681a7f6516ce16a96e18e8455621f8609e32c2b1adc91a7b4a537f66886c212d4e87767ce33776b1279c921574d1c80b5ccee4a1b9069403e038a2ec749b32166b9e06aef812e7e894a0f4fc9fd69c1da44b198ed44093d6421ba62ea2ff8c68017051ee9c0d7da7adfa67f345ff6015ef4365c2e58e00624cc0c772bb6908053a4ff402d455624eef35d921f5452c457ad1ac5b19ad9ea51c38c95e52f30750f183632fb051252fc2ac2e565968e02d4915b9209d5d6ab2a146253e457c39af6c7e8d0fafed4c7c19bc7cd0b61d3bd991a496b70f61d9321f025948e973f096d247d60881e46870db351353e5b099e9bf7eb676cb24f3e28092926987a3fe6f68960908a3744ddcd8bda3ae3323fead7e3744d891b63ee059f7344c8d5c6d4db3907bc51e5fd086fd20947a2c812308c3e39088462c3057f96de2f00d263d318142aeeda57192ffe52253d6bd9c47dfc05409f4c6a3f4d1f3c196ad32c8b51be25a46b28767cccd0f050671fa699bbc733e1ac3b29b98dbff6045706d93e3985738405fd83dc645b21529bf19f49ba5e032554b9435c685d2937f99bb807df4ed754f585c6268d5fd362536631343514dbf3ed10422f72b1766ace3f4d42cc392d7ac53e134bf180286261fbaa527cb9597a2524aa53fb07022461f0ad54dacd4479ee50e786d6c96e83cffdf3182034f3f86656fcbd8aa221fcde7ae1005de87ce09c587f0ee4d6d57c9018717ef005818b2886491a292b087df7e33f999c244d155bd30f6fbf6d0552a0f0636c17ae73a067ebe000211430703e2ae549684a8f1777fdafb8bfec65a400dac360215ff967803d7f468e030e16c2769390f46c4cc30e5f41025295a8a2fcf36142a45240e403c763de62b2ec12db2596dba7e8543a1046af78f6d8268c29c7d618f8f81e2ea52b86f30bc14de12d57aeafdbfae8d98df3b56d9b745d4afda60c1a41ec02e03294289"
                
                +
                "c728559d82327a7444a1c1f3846f097ff9ca2a0cb51197afa2d18584d4dbdc23cd7f9cf5c3b9bac9dc3b20cb8960d4dbe9d1a47a73723e0608322ceed963036694eac7a3274b98e934b4348d488b44d811bbfd30a75bffeee2771f1d511077254f380e535c2c704d8703fe3b49bdf93379ea31a88fdbeb1e6dc195af9012ee4458950ab2ed4775180ffd7df9cc3740ddb258ca7df67b3901d7bfe47337a06512d18f81e9c562f4c157375197f1a007e4d6af49419ad0f793df6d77f3919bb8eb0b25c7f99e1b066fdcdedbfe6a62423c773d2b6a01c3e0a2ca231acaf05816d89771e565b2c16985f12d56f37f8689836527a1e375327021f46bd47dbd18f4ad2b709fccb027e114d763f415b7adba30bc020ad6be86f01d079a3f167075cd93c36bbc3cd137b5e125d69846df95a55aaf6f3eb30ecd374a5791def1d9a043fa3529f0363c8ce3cd4bf15ccaae3009fa7bf6a17194fdbb4ca5464e14ad088b23a3a6eb549083c6518dbd44c90c4663fa6f47f9dcdaa08e34ec0beb6a36aa5c17e758644e15deeea7117e44f37fccee29dcd9d59ca387a655a823f9741c5208723a85fe66a0c30a519fc6c13f2451629798a759e224acbcfee487acebedf755e5ebe239ec89de56accfc6ab5af624969e4f9dceb897a99c0de6049e5a8d18d8de8bbb61a36e20778f137878e71ef731b922c8e2c02e289fdf6b34d4cc61b709a8740c91f96a459a1b1fe05cb61a86722935973a10cb98004240291847fb633e9971f7bbbd6e1755243eaf6536e1614e33f5459a569b0c7b76062184d0327951eb68f431bd1f9ec997dd5aa7c9df4ec6d1dd5e5f16e23c9183ed9b39bc78cd426c299b563a1375b2f5dd3637af8ee96f8889b1cad1884f613c932cf225db3552657eb5ea53d04c496776e9602fff294041da1afc76e5053c718d2d32029f8ffc89d011e1815a8e8bb83840e06c1fdac105fad525fca5e83d9c379648dd0623e54fa5895cda9de376f9305d85118066eca4bd101aeff2f7c229935f0025779ac8b3f80118b9fcf8697ff88bacbd446538d64c992eb824beea7b36fe8ee0c3d522ef85b71ac31b5ea15b93566e2a8fa888ed9ec3becc643e9a75a184bfc0ab13da25527da2adce79e0100e9dffd30ec320913126aaf64d452ca9a9eece2bffc62661ae5a7726e753dce4f8ec39b58965582f89c531a22452a2b367a96be85b1f19879001b92a1d584bf13ead319e46f1ebbdbc4b6917845c4c6ac52ad5f9ab5b2d4b49df38d916a521dfd56f89551294098cea7b9501bf7e302819804c2acf03885c5eacb787ab3a186443f37a5b2cb1e7cdd8cf91416acac99592eac2c45c71f17e179fdaf205b1efa938772d9dbf3d5117759bfde9d418db494d71097ed8afe113e33d33011d92c053614c3c03c275305923c25edc67e17d5a4c1bb2eaad6dfa8a4796ac9c5fdd3c45c0f41efa9cfba4ca5b99fe2e55d73958b9d0752adc571c08b2c20e4ac0162ad2c2d8547332f975d9f1205228bec98e5bed812f598519db82c94ec8d7d6fdd61c799700db73fd3fbe98dbbc620019b42234a6090d1d8844d464f8c59e234d1408226bda7e7b3d3a6c616147a58aeb250e06b9e06307f146a5514d8ab87c6e87c9d301e8e8650518c4b65f4ae32c004bdff5416dfe6cbbf7d94b1390259ef89ccc885a71fd6108bec56ac7f5c0d4de79704bc525f2419f807f2a3c1eb3ac32b01e0c79540cddbd76cd5c192d794e3bb1948d30869ad0587929d5975bc81f0b6d038ab2525911f295bb307124724a108142d10e94dc6a167ece9783fef1a3205e5e58490d16e045990ff8edd4bde356617bfc68f1b6183f6c6a1271ef753b517c72b4fa1a11e1f19d90dc4ee221a8fac42d735db596c6c972c38781c47f9f290cd3caabff61bcfaddd26bd3317f419a08a3e2b402f7bd2379710517b12778c0ecd1cc15542332f2f7303f9e0be6c81f3626b9228d6b6273e6010f579311"
                
                +
                "24c5a8d3bf953297e97a50f3564fddfa0112bdef8255723513cfb0af2ed4f4ba98bea71d6f0da450b9401b100939cce134da0f6042ab8e7f87d06726b1cb38e20657caf30bf76eaf4fae91e86a920cd929d36b82a945873e4bd9f3fa6fa2e75c8299ec438c1c73b86bf2cdbf7046b721296a8537b523da2d3eb3c83ceb6d17eef30539b71903f9da54d48109628deabd878545e406c23ec3b3b46407a9d26e323cbb6e4284b4ece4d569564f2cbaf699fd65e6bf5a77fd63db82cd4a125adbfab7b6f41cae6b176681445da10212772e2417a43b748150f6ef10d205279e9b9df7df3a16a0664d0406475e5b93f222030ab489ba3be682393750cad88399ff2278532c1938e39186db1c1ad753d4e315f0342c3f78774e7b5a3122141ed68f13978fdd79ae91233431781ea2338abb0dea72c78c9c583813f9dff4d2bd36fdabc88167a4d238e66eaee15ca10b8f9e8444f6753f746ae98a66705ce2d445ee0502d2a96bf610bd54b9192bc5b55aaf19adb84b1e69edb8f6d8d65b91141dd4e11c2e0b4ee8f826efcf4ab12dd74380a307f29836bc42d90ed9da39753a0f74fa552d6e72d8b93d148fa4b6fcf2cab550b88829f810bc5123e227a40d4fb2719cd8335076e4ec1e43e7ef1003cb2db28795ed5f7302a35c52b7f9fbf463e3686c8bb12119301b54d77b71bf914f97cf20667b1aba1c76f9a89ea417de30f9d70fd7c2383853d565c488973ccf7ce3d17481749bf7c1c128bab12e9de59ce6fa4ffeaec6e90961f138d9a8c2b72af694fe271c0b2f7d14e6c80b4f57e34bf196143ff33b1cf9cd04c57170786027c4df83dcf244d573a3b4de1907d8feb974b70f3f24cbbd62b2008ddb97af8317f4240194ac824c7c6efcf76656776e50b148dcce2eb603c51e14d4fc305139f50172fb755ba84f03f4e5eff1138cc8436664e7d3f9e646151c15dcf16a6da54ac94dc855f1114fa24c06ded65b108cdfef5d2eccee3c5e2629d0f7c5db7724a19c89435db9d0b5d064382aae296e98ad22c5aa88c28065470772c9392c5ad7b1dadec4a85dff9cec68842ad405d2a148b93937e0d42ed42d0760aece7539b4a5279aba5c38ce727049d073db5ada6226f54a11f1fb80a27f1b8a7e7be0f8f52202f5999d6a89f4e015ade46a8196d869d7e493c31df221fb159125b0d659656bb0201f79df3821c3d64e93498bd231639ed1bef45b0a7b202b8e276fb1fcc48e861584c92f8b1008f3e52821e2dfe257e40176fb024d0974b3598429ac99d8cc22492420cf7e4740821b3cec6cbf009934fe8f9d916df6e5d3b02ceb670c1f241286be1693a621acc6c8e9160fb17cae2e0413de363a9fac8868288c4245b57c5d8abaa334b60b50adbb56d3d93d82adeb2c03846993f4aa1282ecd41a40b8f8a4f148b3369782a858cbaa10086a70aa894006469004ca438a178690451c3b909ef0d8da762ace46a29bf214550c69e49fa8abd2b90615ac69d84559dda4c7a1995d88991eebadbaabc934c4e1ab7688a06bea8ad2c9d0d9c68acf4ec0c41c12ef241824de32df6c869988c8159d268f71aee56e7266410d8c9355a6ca53b405bed48210dce2b769cfa51948cc8f51b5ee06d5368ad8a9aa215ca5b4c146ae9c937e46a94ac174d6c9c6abfb1fa05646080a4ca534bce50ab3e68810626ad7e1897216c978353862e3d8f63bbc169226f067826ab7f9b8613645092027f3f0cc6c234f7745f718e7794c641a4c97699a5d6140f79869a993e457eafb3bc2e6c63d4cc3287ec0feeb813b8b74897779d01fddeca0ec3c5a0a4c1883e39a3eedd9d31a47be49ab8eb96feb5765513d06032bc156e1bffa2617dac7ff35e0da1f0da90ee695e2a6536a698eb73a354965fd7b098cf46de1dc44128f581575bc21c561736035ba"
            ]
            ] as [String : Any]
        
        var parsedPackets = [String: Any]()
        for (key, value) in rawPackets {
            if let hexPacket = value as? String {
                parsedPackets[key] = try self.parse(tcpHex: hexPacket)
            }else if let hexArray = value as? [String] {
                var packets = [ContinuityPacket]()
                for hexPacket in hexArray {
                    packets.append(try  self.parse(tcpHex: hexPacket))
                }
                parsedPackets["Data"] = packets
            }
        }
        
        return parsedPackets
    }
}
