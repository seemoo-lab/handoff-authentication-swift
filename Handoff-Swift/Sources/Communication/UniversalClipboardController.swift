//
//  UniversalClipboardController.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 04.07.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation
import CoreServices

/// This struct is responsible for handling universal clipboard data. It will use general Handoffhandlers for encrypting and decrypting data
class UniversalClipboardController {
    /// Current pairing session.
    let ps: PairingSession!
    var handoffHandler: HandoffHandler
    let connection: ContinuityConnection
    
    var lastRequestId = 0
    var lastAction: UniversalClipboardController.ClipboardActions = .requestSystemInfo
    
    /// Sometimes packets have to be transmitted over multiple packets. This packet is partially complete
    var partialPacket: ContinuityPacket?
    
    /// Initialize with a pairing session to get a shared secret for communication
    ///
    /// - Parameter pairingSession: A fully finished PairingSession with a setup connection
    init(withPairingSession pairingSession: PairingSession, mode: HandoffMode) throws {
        self.ps = pairingSession
        guard let conn = pairingSession.connection else {throw HandoffError.noConnection}
        self.connection = conn
        self.handoffHandler = try HandoffHandler(withPairingSession: ps, andMode: mode)

        
        self.connection.delegate = self
    }
    
    
    /// This function generates a system info dictionary that can be sent to the server/client and be understood by the receiving side
    ///
    /// - Returns: System info dictionary
    func generateSystemInfo() -> [String: Any] {
        
        //See [RPConnection systemInfo]
        let systemInfo: [String: Any] = [
            "_bf": 0, //Bonjour Flags & Companion Link Flags (_RPBonjourFlagsUpdateWithRPCompanionLinkFlags)
            "_cf": 512, //Control Flags
            "_clFl": 128, // Local Device Info Flags
            //"_dC": "#272728", //Device color. Not used for macOS. Only on iOS
            "_i": "2a8479299665", // Local device Info identifier.
            "_idsID": PairingDevice.current.config.pairingIdentity, //IDS Device identifier
            "_pubID": "28:7D:F2:C2:99:B6", //Public identifier
            "_sf": 256, //Status Flags
            "_sv": "170.18", //Hardcoded string
            "model": "MacBookPro11,5", //Device Model (MacBookPro11,5)
            "name": "Alexander’s MacBook Pro" //Device name (Alexanders MacBook Pro)
        ]
        
        print("Sending system info:\n ", systemInfo)
        
        return systemInfo
    }
    
    
    //MARK: Client mode
    
    
    /// This method will request the system info of the connected system
    ///
    /// - Throws: An error if something fails
    func requestSystemInfo() throws {
        let currentRequestId = arc4random()
        let requestDictionary: [String : Any] = [
            RequestKeys.info: RequestTypes.systemInfo,
            RequestKeys.mode : 2,
            RequestKeys.requestId: currentRequestId,
            RequestKeys.content: generateSystemInfo()
        ]
        self.lastRequestId = Int(currentRequestId)
        
        //Encode using OPACK
        let encoded = try OPACKCoding.encode(fromDictionary: requestDictionary)
        let bodySize = encoded.count
        
        let header = ContinuityPacket.Header(firstByte: .encryptedData, bodySize: bodySize)
        
        //Encrypt with HandoffHandler
        var packet = ContinuityPacket(header: header, body: encoded)
        packet = try self.handoffHandler.handleEncrypt(withPacket: packet)
        
        //Send packet
        try self.connection.send(packet: packet)
        
        //Check for response in delegate
    }
    

    func requestPasteboardTypes() throws {
        let currentRequestId = lastRequestId + 1
        
        let deviceUUID = PairingDevice.current.config.pairingIdentity
        
        let requestDictionary: [String : Any] = [
            RequestKeys.info : RequestTypes.handoffPayloadRequest,
            RequestKeys.requestId: currentRequestId,
            RequestKeys.mode: 2,
            RequestKeys.content: [
                RequestKeys.ContentKeys.advPayload: "<a1072cb8b f1d9818ac>".hexadecimal!,
                RequestKeys.ContentKeys.clientCommand: "pbtypes",
                RequestKeys.ContentKeys.identifier: deviceUUID
            ]
        ]
        
        self.lastRequestId = currentRequestId
        self.lastAction = .requestPasteboardTypes
        
        let encoded = try OPACKCoding.encode(fromDictionary: requestDictionary)
        
        let header = ContinuityPacket.Header(firstByte: .encryptedData, bodySize: encoded.count)
        
        var packet = ContinuityPacket(header: header, body: encoded)
        packet = try self.handoffHandler.handleEncrypt(withPacket: packet)
        
        //Send
        log("Sending pbtypes request")
        log(requestDictionary)
        try self.connection.send(packet: packet)
        //Check for response in delegate
    }
    
    func requestPasteboard() throws {
        let currentRequestId = lastRequestId + 1
        
        let deviceUUID = PairingDevice.current.config.pairingIdentity
        
        let requestDictionary: [String : Any] = [
            RequestKeys.info : RequestTypes.handoffPayloadRequest,
            RequestKeys.requestId: currentRequestId,
            RequestKeys.mode: 2,
            RequestKeys.content: [
                RequestKeys.ContentKeys.advPayload: "<70627479 70657321>".hexadecimal!,
                RequestKeys.ContentKeys.clientCommand: "pbpaste2",
                RequestKeys.ContentKeys.identifier: deviceUUID
            ]
        ]
        
        self.lastRequestId = currentRequestId
        self.lastAction = .requestPasteboardTypes
        
        let encoded = try OPACKCoding.encode(fromDictionary: requestDictionary)
        
        let header = ContinuityPacket.Header(firstByte: .encryptedData, bodySize: encoded.count)
        
        var packet = ContinuityPacket(header: header, body: encoded)
        packet = try self.handoffHandler.handleEncrypt(withPacket: packet)
        
        //Send
        log("Sending pbpaste2 request")
        try self.connection.send(packet: packet)
        //Check for response in delegate
    }
    
    //MARK: Responses
    
    
    
    func handleResponse(forPacketContent packetContent: [AnyHashable: Any]) {
        //Check for errors
        if let errorMessage = packetContent["_em"] as? String {
            //Error detected
            log("Error in response \(errorMessage)")
            return
        }
        
        switch lastAction {
        case .requestSystemInfo:
            self.handleSystemInfoResponse(withContent: packetContent)
        case .requestPasteboardTypes:
            self.handlePasteboardTypesResponse(withContent: packetContent)
        case .requestPasteboardData:
            self.handlePasteboardTypesResponse(withContent: packetContent)
            
        }
    }
    
    func handleSystemInfoResponse(withContent content: [AnyHashable: Any]) {
        //Request pasteboad types
        do {
            try self.requestPasteboardTypes()
        }catch let error {
            log("Requesting pasteboard types failed \(error)")
        }
        
    }
    
    func handlePasteboardTypesResponse(withContent content: [AnyHashable: Any]) {
        //Get the pasteboard archived data
        guard let bodyDict = content["_c"] as? [AnyHashable: Any],
            let pasteboardData = bodyDict["rActPayload"] as? Data else {
            log("Failed getting pasteboard data")
            return
        }
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
        }catch let error {
            log(error)
        }
        
        
    }
    
    func getTypeFromPasteboard(pasteboardData: Data, type: String) -> Data?  {
        let unarchiver = try! NSKeyedUnarchiver(forReadingFrom: pasteboardData)
        let pasteboardInfoWrapper = unarchiver.decodeObject(of: UASharedPasteboardInfoWrapper.self, forKey: NSKeyedArchiveRootObjectKey)
        let pasteboardData = pasteboardInfoWrapper!.extraData!
        
        //Extract the given type
        for itemInfo in pasteboardInfoWrapper!.pbInfo!.items! {
            guard let types = itemInfo.types,
                let pngTypeInfo = types[type] as? UASharedPasteboardTypeInfo else {return nil}
                       
           let dataStart = pasteboardData.startIndex.advanced(by: pngTypeInfo.offset?.intValue ?? 0)
           let dataEnd = dataStart + (pngTypeInfo.size ?? 0)
           return pasteboardData[dataStart...dataEnd]
        }
        
        return nil
    }
    
    
    //MARK: - Server mode
    
    func handleRequest(forPacketContent packetContent: [AnyHashable: Any]) {
        
    }


    func handleEncryptedPacket(continuityPacket packet: ContinuityPacket)  {
         let bodySize = packet.header.expectedDataSize()
        
        guard packet.body.count == bodySize else {
            log("Packet not complete. \(packet.body.count)/\(bodySize)")
            //Packet delivery not finished
            self.partialPacket = packet
            return
        }
        do {
            //Decrypt packet
            let decrypted = try self.handoffHandler.handleDecrypt(continuityPacket: packet)
            
            if let requestId = decrypted[RequestKeys.requestId] as? Int,
                requestId == lastRequestId {
                self.handleResponse(forPacketContent: decrypted)
            }else {
                log("Cannot handle.")
                fatalError("Handling packet failed")
            }
        }catch let error {
            log("Failed Decrypting \(error)")
        }

    }
}

//MARK: - Delegates

extension UniversalClipboardController: ConnectionDelegate {
    func receivedData(_ data: Data) {
        log("Received data \n\(data.hexadecimal)")
        log("\(data.count)bytes")
        //Append to partial packet
        if let partial = self.partialPacket {
            var packetData = partial.body
            packetData.append(data)
            let header = partial.header
            
            let packet = ContinuityPacket(header: header, body: packetData)
            
            if header.expectedDataSize() == packetData.count {
                self.partialPacket = nil
                self.receivedPacket(packet)
            }else {
                self.partialPacket = packet
            }
        }
    }
    
    func receivedPacket(_ packet: ContinuityPacket) {
        print("Received packet")
        log(packet.data.hexadecimal)
        
        do {
            //Check if packet is encrypted
            let headerByte = packet.header.type!
            
            switch headerByte {
            case .encryptedData:
               self.handleEncryptedPacket(continuityPacket: packet)
                
            default:
                log("Unknown header")
            }
            
        }catch let error {
            print("Error occured \(error)")
        }
    }
    
    
}

//MARK: - Structs and Enums
extension UniversalClipboardController {
    struct RequestKeys {
        /// Type of the request
        static let info = "_i"
        /// Describes wether this is a request (client mode) t=2 or a response (server mode) t=3
        static let mode = "_t"
        /// The current request's id. Is normally a random number. Does not change for the response
        static let requestId = "_x"
        /// The content of the request / response
        static let content = "_c"
        
        struct ContentKeys {
            static let advPayload = "rAdvPayload"
            static let clientCommand = "rClientCommand"
            static let identifier = "rIdentifier"
        }
    }
    
    struct RequestTypes {
        static let systemInfo = "_systemInfo"
        static let handoffPayloadRequest = "com.apple.handoff.payload-request"
    }

    enum ClipboardActions {
        case requestSystemInfo
        case requestPasteboardTypes
        case requestPasteboardData
    }
}
