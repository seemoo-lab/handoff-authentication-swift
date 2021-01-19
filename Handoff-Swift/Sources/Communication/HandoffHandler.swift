//
//  HandoffHandler.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 26.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

struct HandoffHandler {
    let sharedSecret: Data
    let mode: HandoffMode
    
    private var cryptor: HandoffCryptor
    
    /// Initialize the handler with a finished pairing session so it can access the shared secret
    ///
    /// - Parameter withPairingSession:
    /// - Throws: An error if the pairing is not complete
    init(withPairingSession ps: PairingSession, andMode mode: HandoffMode) throws {
        guard let sharedSecret = ps.sharedSecret else {
            throw HandoffError.pairingIncomplete
        }
        self.sharedSecret = sharedSecret
        
        self.mode = mode
        
        //Cryptor is used for actual encryption and decryption
        self.cryptor = HandoffCryptor(withSharedSecret: sharedSecret, andMode: mode)
    }
    
    init(withSharedSecret secret: Data, andMode mode: HandoffMode) {
        self.sharedSecret = secret
        self.mode = mode
        
        //Cryptor is used for actual encryption and decryption
        self.cryptor = HandoffCryptor(withSharedSecret: sharedSecret, andMode: mode)
    }
    
    
    /// Decrypt a continuity packet and return the contained dictionary
    ///
    /// - Parameter continuityPacket: Continuity packet that contains encrypted content
    /// - Returns: Dictionary of content if available
    /// - Throws: Error if decryption or decoding fails
    mutating func handleDecrypt(continuityPacket: ContinuityPacket) throws -> [AnyHashable: Any] {
        //Decrypt the packet data first
        let decrypted = try self.cryptor.decrypt(continuityPacket: continuityPacket)
        
        //Opack decode the data
        let dict = try OPACKCoding.decode(fromData: decrypted)
        
        log("Decrypted OPACK Content")
        log(dict)
        
        return dict
    }
    
    
    mutating func handleEncrypt(withPacket continuityPacket: ContinuityPacket) throws -> ContinuityPacket {
        let body = continuityPacket.body
        let aad = continuityPacket.header.data
        
        let chachaOut = try self.cryptor.encrypt(data: body, aad: aad)
        //Append the auth tag on the end
        var encryptedData = chachaOut.encrypted
        encryptedData.append(chachaOut.authTag)
        
        let encryptedPacket = ContinuityPacket(header: continuityPacket.header, body: encryptedData)
        
        return encryptedPacket
    }
    
    
    mutating func handle(continuityPacket: ContinuityPacket) throws {
        let dict = try self.handleDecrypt(continuityPacket: continuityPacket)
        
        //Handle the message
        if let messageContent = dict[HandoffMessageKeys.content] {
            if let contentDict = messageContent as? [AnyHashable: Any] {
                if let payloadData = contentDict[HandoffMessageKeys.rActPayload] as? Data {
                    self.handleDataMessage(data: payloadData)
                }
            }
        }
    }
    
    func handleDataMessage(data: Data) {
        //Try to stringfy
        let dataString = String(data: data, encoding: .ascii)
        log(dataString )
        
        //Check if plist
        if dataString?.contains("plist") == true {
            //Decode plist
            let plistDict = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            log(plistDict)
            //Write to file
            try? data.write(to: URL(fileURLWithPath: "/Users/AlexSFD/Downloads/clipboard_plist.plist"))
        }
        
    }

    enum HandoffError: Error {
        case pairingIncomplete
    }
    
    
    struct HandoffMessageKeys {
        static let content = "_c"
        static let rActPayload = "rActPayload"
    }
}

enum HandoffMode {
    case client
    case server
}


