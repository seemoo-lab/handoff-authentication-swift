//
//  MessageDecrypter.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 25.07.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation


class MessageDecryptor {
    /// Used to decrypt messages
    var sharedSecret: Data!
    var dataPackets: [ContinuityPacket]!
    
    
    init(sharedSecret: String, packets: [String:  Any]) {
        self.sharedSecret = sharedSecret.hexadecimal!
        self.dataPackets = packets["Data"] as? [ContinuityPacket]
    }
    
    func decrypt() throws {
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
            
            if decrypted == nil {
                throw NSError(domain: "Decyption", code: -1, userInfo: ["msg": "Decryption failed"])
            }
        }
    }
    
    private func handleDecryptedData(_ decrypted: Data) throws  {
        let content  = try OPACKCoding.decode(fromData: decrypted)
        
        guard let t = content["_t"] as? Int else {return}
        
        switch t {
        case 2:
            self.handleClientRequest(content: content)
        case 3:
            self.handleServerResponse(content: content)
        default:
            log("No matching parser found")
        }
       
    }
    
    private func handleServerResponse(content: [AnyHashable: Any]) {
        log("-------\n Server Response: \n-------")
        
        //Get the pasteboard archived data
        guard let bodyDict = content["_c"] as? [AnyHashable: Any] else {
            log("No content found")
            return
        }
        
        if let pasteboardData = bodyDict["rActPayload"] as? Data {
            self.handleUASharedPasteboardInfo(pasteboardData: pasteboardData)
        }else {
            log(content)
        }
        

    }
    
    private func handleUASharedPasteboardInfo(pasteboardData: Data) {
        //Unarchive the class
        do {
            let unarchiver = try NSKeyedUnarchiver(forReadingFrom: pasteboardData)
            let pasteboardInfoWrapper = unarchiver.decodeObject(of: UASharedPasteboardInfoWrapper.self, forKey: NSKeyedArchiveRootObjectKey)
            //Retrieved pasteboard info wrapper
            
            log(pasteboardInfoWrapper)
            
            pasteboardInfoWrapper?.pbInfo?.items?.forEach({ (itemInfo) in
                itemInfo.types?.forEach({ (key, value) in
                    if let keyString = key as? String,
                        let typeInfo = value as? UASharedPasteboardTypeInfo {
                        
                        log("\(keyString): \n\(typeInfo.description) \n\n")
                    }
                })
            })
            
            if let extraData = pasteboardInfoWrapper?.extraData {
                let extraDataString = String(data: extraData, encoding: .ascii)
                log("Extra Data")
                log(extraDataString!)
            }
        
            
        }catch let error {
            log(error)
        }
    }
    
    private func handleClientRequest(content: [AnyHashable: Any]) {
        log("------\nRequest: \n------")
        log(content)
    }
}
