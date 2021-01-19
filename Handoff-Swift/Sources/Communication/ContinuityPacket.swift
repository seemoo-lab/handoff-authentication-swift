//
//  ContinuityPacket.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 17.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

protocol ContinuitySendable {
    var data: Data { get }
}

/// A wrapper for a continuity packet that will be sent over TCP. It enables easy combination of the header and the body of that packets
struct ContinuityPacket: ContinuitySendable {
    let body: Data
    var header: Header
    
    
    /// Binary data that can be sent.
    var data: Data {
        var packet = Data(header.data)
        packet.append(body)
        return packet
    }
    
    
    /// Initialize with just data. The first 4 bytes **MUST** represent a header
    ///
    /// - Parameter data: Complete TCP Data that include the header in the first 4 bytes
    init(data: Data) throws {
        let header = data[0..<4]
        let body = data[4...]
        
        self.header = try Header(data: header)
        self.body = body
    }
    
    /// Initialize with header data and body data in raw
    ///
    /// - Parameters:
    ///   - headerData: 4 bytes header. If less or more the init will throw
    ///   - body: The body that should be sent
    /// - Throws: If the header size is wrong
    init(headerData: Data, body: Data) throws {
        self.header = try Header(data: headerData)
        self.body = body
    }
    
    
    /// Initialize with a header type and the body
    ///
    /// - Parameters:
    ///   - header: Header as ContinuityPacket.Header
    ///   - body: Raw Body
    init(header: Header, body: Data) {
        self.header = header
        self.body = body
    }
    
    
    /// Initializes the packet and generates the header from the given header type
    ///
    /// - Parameters:
    ///   - headerType: The header type defines where it is used for
    ///   - body: Raw body
    init(headerType: Header.FirstByte, body: Data) {
        self.header = Header(firstByte: headerType, bodySize: body.count)
        self.body = body
    }
    
    
    
    /// Decode the packet body using OPACK
    ///
    /// - Returns: OPACK decoded dictionary
    /// - Throws: If decoding fails
    func opackDecoded() throws -> [AnyHashable: Any] {
        let decoded = try OPACKCoding.decode(fromData: self.body)
        
        return decoded
    }
    
    /// While pairing the packets are OPACK Encoded and contain pairing Data. This pairing Data is encoded in a TLV8. This function will return the pairing TLV in one call
    ///
    /// - Returns: a pairing TLV if the packet contains one
    /// - Throws: If parsing fails or no TLV is contained 
    func pairingTLV() throws -> TLV8Box {
        let opackDict = try self.opackDecoded()
        guard let pairingData = opackDict[PairingSession.Constants.pairingDataKey] as? Data else {
            throw TLVError.parsingFailed
        }
        
        let tlv = try TLV8Box.deserialize(fromData: pairingData)
        
        return tlv
    }
    
    
}

extension ContinuityPacket  {
    enum PacketError: Error {
        case headerSize
        case unknownHeader
    }
}

//MARK:- Header
extension ContinuityPacket {
    struct Header {
        private var headerBytes = Array<UInt8>(repeating: 0x00, count: 4)
        
        var data: Data {
            return Data(headerBytes)
        }
        
        var type: FirstByte! {
            return FirstByte.init(rawValue: headerBytes[0])!
        }
        
        init(data: Data) throws {
            guard data.count == 4 else {
                throw PacketError.headerSize
            }
            
            guard FirstByte(rawValue: data[0]) != nil else {
                throw PacketError.unknownHeader
            }
            
            self.headerBytes = Array(data)
        }
        
        init(firstByte: FirstByte, bodySize: Int) {
            var bSize = UInt16(bodySize)
            if firstByte == .encryptedData {
                //Increase by 16 for the auth tag
                bSize += 16
            }
            
            let bodySizeBigEndian = bSize.data.toBigEndianArray()
            
            var hBytes = [firstByte.rawValue, 0x00]
            hBytes.append(contentsOf: bodySizeBigEndian)
            
            headerBytes = hBytes
        }
        
        func expectedDataSize() -> Int {
            let dataSizeArray = Array(self.headerBytes[1...])
            
            var dataSize = 0
            dataSize += Int(pow(16.0, 4.0)) * Int(dataSizeArray[0])
            dataSize += Int(pow(16.0, 2.0)) * Int(dataSizeArray[1])
            dataSize += Int(pow(16.0,0.0)) * Int(dataSizeArray[2])
            
            return dataSize
        }
        
        /// The first byte in the header defines which content the packet will contain. It marks how it is encoded and what should be done with it
        ///
        /// - startPairing: Not used in continuity as pairing should be finished
        /// - pairingSetup: Not used in continuity as pairing should be finished
        /// - pairVerifyPublicKey: Initialized the verification Process
        /// - pairVerifyContinue Answer to pairVerify. Contains encrypted data with shared secret and the public key
        /// - encryptedData: Encrypted data will be sent
        enum FirstByte: UInt8 {
            
            case startPairing = 0x03
            case pairingSetup = 0x04
            case pairVerifyPublicKey = 0x05
            case pairVerifyContinue = 0x06
            case encryptedData = 0x08
            case finished = 0x01 
        }
    }
    
}
