//
//  PairingSession.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 28.05.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

protocol PairingSessionDelegate {
    func didFinishPairing(withPairingSession pairingSession: PairingSession)
}

class PairingSession {
    var sessionKeys: CurveKeyPair
    var sharedSecret: Data?
    var delegate: PairingSessionDelegate?
    
    var peerPublicKey: Data?
    var peerAppFlags: Int?
    var peerPairingIdentity: PairingIdentity?
    
    var connection: ContinuityConnection?
    
    init() throws {
        
        let hkdfSpec = KeyGeneration.HKDFInfo(info: "Pair-Verify-ECDH-Info", salt: "Pair-Verify-ECDH-Salt", keyLength: KeyGeneration.Constants.curveKeyLength)
        self.sessionKeys = try KeyGeneration.generateCurve25519RandomKeypair(usingHKDF: hkdfSpec)
    
    }
    
    
    /// Setup a TCP connection to a specific IP address. When the connection is setup the pairing can be started
    ///
    /// - Parameter service: Connect the PairingSession to a discovered Bonjour service
    func connect(to service: BonjourService)throws  {
        connection = try ContinuityConnection(withService: service)
        connection?.delegate = self
        try connection?.connect()
    }
    
    
    /// Initiate the key exchange process when a connection has been made
    func startKeyExchange() throws {
        guard let connection = self.connection else {throw PairingError.noConnection}
        
        // Send own packet
        log("Sending first packet with public Key -- M1")
        let intialPacketData = try createInitializePairingData()
        let pairingData = try opackPairingData(fromSerializedTLV: intialPacketData)
        let firstPacket = ContinuityPacket(headerType: .pairVerifyPublicKey, body: pairingData)
        try connection.send(packet: firstPacket)
        
        //Wait for the answer
    }
    
    //MARK:- Data packets
    
    /// All communication uses an OPACK encoded dictionary with pairing data stored in "_pd" key. This pairing data is TLV8 formatted. This method uses OPACK to encode the serialized TLV8 in such a dictionary
    ///
    /// - Parameter tlv: Serialized TLV8 Data
    /// - Returns:OPACK encoded data
    func opackPairingData(fromSerializedTLV tlv: Data) throws -> Data {
        let opackDict = [
            Constants.pairingDataKey: tlv
        ]
        let encoded = try OPACKCoding.encode(fromDictionary: opackDict)
        
        return encoded
    }
    
    func createInitializePairingData() throws -> Data {
        //The first packet that is sent to setup a pairing session contains the state set to 1 and the public key that has been generated for this session. The keypair can be deleted after one session as it is only important for generating a shared secret using ECDH.
        
        //1. Generate a TLV Box
        var tlvBox = TLV8Box()
        //Add the public key TLV
        let pubKeyData = sessionKeys.publicKey
        tlvBox.addValue(withType: PairingTLV.publicKey, andLength: UInt8(crypto_box_PUBLICKEYBYTES), andValue: pubKeyData)
        log("Creating pairing packet with public key: \(pubKeyData.hexadecimal)")
        //Add the packet number (state)
        tlvBox.addInt(withType: PairingTLV.state, andValue: 1)
        //Add the value for 0x19 (guessing that this means the pairing should start).
        tlvBox.addInt(withType: PairingTLV.appFlags, andValue: 1)
        
        return try tlvBox.serialize()
    }
    

    
    func parsePairingPacket(_ packet: ContinuityPacket) {
        do {
            //Get the pairing TLV from the packet 
            let tlv = try packet.pairingTLV()
            
            guard let value = tlv.getValue(forType: PairingTLV.state),
                let state = value.first else {
                throw PairingError.parsingFailed
            }
            

            
            
            switch state {
            case 0x1:
                log("Pair-verify client M1 -- received start request")
                try self.receivedStartRequest(pairingTLV: tlv)
            case 0x2:
                log("Pair-verify client M2 -- start response")
                try self.receivedStartPairingResponse(responseTLV: tlv)
                
            case 0x4:
                try self.receivedPairVerifyFinishResponse(packetTLV: tlv)
                
            default:
                log("Unknown state \(state)")
//                fatalError("Unknown state")
            }
            
        }catch let error {
            log("Error during decoding \(error)")
        }
    }

    //MARK: First packet M1
    func receivedStartRequest(pairingTLV: TLV8Box) throws {
        guard let peerPublicKey = pairingTLV.getValue(forType: PairingTLV.publicKey) else {
            throw PairingError.parsingFailed
        }
        
        self.peerPublicKey = peerPublicKey
        
        self.sharedSecret = try KeyGeneration.curve25519(secretKey: self.sessionKeys.secretKey, base: peerPublicKey)
        
        try self.sendPairingVerifyStartResponse()
       
    }
    
    func sendPairingVerifyStartResponse() throws {
        guard let peerPublicKey = peerPublicKey else {
            throw PairingError.keyExchangeFailed
        }
        
        //After the shared secret has been generated
        //Create Data that should be signed with the current device signing key
        //The data that should be signed is the concatenation of the current public key + the peers public key
        var dataToSign = Data(capacity: self.sessionKeys.publicKey.count + peerPublicKey.count)
        dataToSign.append(self.sessionKeys.publicKey)
        dataToSign.append(peerPublicKey)
        
        let signingKeys = PairingDevice.current.signingKeys
        
        //Sign the data
        let signature = Signing.signWithEd25519(message: dataToSign, pk: signingKeys.edPublicKey, sk: signingKeys.edSecretKey)
        
        //Generate a sub TLV that will be encrypted
        var tlv = TLV8Box()
        tlv.addValue(withType: PairingTLV.signature, andLength: UInt8(signature.count), andValue: signature)
        let tlvData = try tlv.serialize()
        
        guard tlvData.count == 85 else {throw PairingError.signingFailed}
        
        //Encrypt serialized TLV
        //TODO:
    }
    
    //MARK: Second packet M2
    func receivedStartPairingResponse(responseTLV: TLV8Box) throws {
        //This packet contains the peer's public key 0x03, an encrypted TLV (0x05) and state = 2 (0x06)
        guard let peerPublicKey = responseTLV.getValue(forType: PairingTLV.publicKey) else {
            throw PairingError.parsingFailed
        }
        self.peerPublicKey = peerPublicKey
        
        //1. Generate the shared Secret
        let sharedSecret = try KeyGeneration.curve25519(secretKey: self.sessionKeys.secretKey, base: peerPublicKey)
        self.sharedSecret  = sharedSecret
        
        //2. Generate the decryptionKey
        let decryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
        
        //3. Decrypt the data
        guard let encrypted = responseTLV.getValue(forType: PairingTLV.encryptedData) else {throw PairingError.parsingFailed}
        let nonce = "PV-Msg02".data(using: .ascii)!
        
        let decrypted = try Crypto.chachaPoly1305Decrypt64x64(key: decryptionKey, nonce: nonce, aad: nil, encrypted: encrypted)
        
        //4. Verify decrypted Data
        //Should be a TLV
        let tlv = try TLV8Box.deserialize(fromData: decrypted)
        guard let signature = tlv.getValue(forType: PairingSession.PairingTLV.signature),
            let appFlags =  tlv.getValue(forType: PairingSession.PairingTLV.appFlags) else {
                throw PairingError.parsingFailed
        }
        
        // Verify the signature to ensure the partner is valid
        do {
            let pairingIdentity = try PairingVerifier(publicKey: self.sessionKeys.publicKey, peerPublicKey: peerPublicKey).verifySignatureFromPeer(signature)
            self.peerPairingIdentity = pairingIdentity
        }catch let error {
            log("Validation failed")
            log(error)
            //Also accept not validated signtares, but log the error
        }
        
        self.peerAppFlags = Int(appFlags.first!)
        //Create an answer packet and send it
        try self.sendPairVerifyFinishRequest()
    }
    
    //MARK: Packet M3
    func sendPairVerifyFinishRequest() throws {
        guard let peerPublicKey = self.peerPublicKey,
            let sharedSecret = self.sharedSecret else {
                throw PairingError.noPeerPublicKeyAvailable
        }
        
        //1. Sign the public keys
        
        var message = self.sessionKeys.publicKey
        message.append(peerPublicKey)
        
        let signature = Signing.signWithEd25519(message: message, pk: PairingDevice.current.signingKeys.edPublicKey, sk: PairingDevice.current.signingKeys.edSecretKey)
        
        //2. Create a TLV with the signature
        var tlv = TLV8Box()
        tlv.addValue(withType: PairingTLV.signature, andLength: UInt8(signature.count), andValue: signature)
        
        //3. Encrypt the TLV with the shared secret
        let encryptionKey = KeyGeneration.cryptoHKDF(input: sharedSecret, outLength: KeyGeneration.Constants.curveKeyLength, salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info")
        
        let tlvData = try tlv.serialize()
        
        let nonce = "PV-Msg03".data(using: .ascii)!
        
        let result = try Crypto.chachaPoly1305Encrypt64x64(key: encryptionKey, nonce: nonce, aad: nil, message: tlvData)
        
        var encryptedData = result.encrypted
        encryptedData.append(result.authTag)
        
        //4. Construct answer packet
        var answerTLV = TLV8Box()
        answerTLV.addValue(withType: PairingTLV.encryptedData, andLength: UInt8(encryptedData.count), andValue: encryptedData)
        answerTLV.addInt(withType: PairingTLV.state, andValue: 0x03)
        
        let answerTLVBytes = try answerTLV.serialize()
        let packetBody = try OPACKCoding.encode(fromDictionary: ["_pd" : answerTLVBytes])
        
        //6. send the packet
        log("Sending Pair Verify M3")
        let header = ContinuityPacket.Header(firstByte: .pairVerifyContinue, bodySize: packetBody.count)
        let packet = ContinuityPacket(header: header, body: packetBody)
        try connection?.send(packet: packet)
    }
    
    //MARK: Packet M4
    
    
    /// Received an answer for the Pair Verify Finish Request. This is the last package in the Pair-Verify protocol. All traffic afterwards is encrypted
    ///
    /// - Parameter packetTLV: The packet's TLV. Should only contain a state
    /// - Throws: Errors if the Server has responded with an invalid state
    func receivedPairVerifyFinishResponse(packetTLV: TLV8Box) throws {
        let state = packetTLV.getValue(forType: PairingTLV.state)?.first
        
        guard packetTLV.getTypes().count == 1,
            state == 0x04 else {
            throw PairingError.peerFailed
        }
        
        //Finished!
        log("Pairing Session finished")
        self.delegate?.didFinishPairing(withPairingSession: self)
    }
}

//MARK:- Connection Delegate
extension PairingSession: ConnectionDelegate {
    func receivedData(_ data: Data) {
        log("Received data \(data.hexadecimal)")
    }
    
    func receivedPacket(_ packet: ContinuityPacket) {
        guard let packetType = packet.header.type else {
            log("Unknown packet type")
            return
        }
        //Perform action based on type
        switch packetType {
        case .pairVerifyPublicKey:
            self.parsePairingPacket(packet)
        case .pairVerifyContinue:
            self.parsePairingPacket(packet)
            
        default:
            log("Received unknown response. Stopping authentication")
            
        }
    }
}

enum PairingError: Error {
    case keyGenerationFailed
    case noConnection
    case noPairingDataFound
    case parsingFailed
    case keyExchangeFailed
    case signingFailed
    case peerVerificationFailed
    case noPeerPublicKeyAvailable
    case peerFailed
}

extension PairingSession {
    enum PairingTLV: TLVType {
        
        case state
        case publicKey
        case appFlags
        case appleIDCertificateData
        case signature
        case encryptedData
        case identityId
        
        
        var uInt8: UInt8 {
            switch self {
            case .publicKey:
                return 0x03
            case .state:
                return 0x06
            case .appFlags:
                return 0x19
            case .appleIDCertificateData:
                return 9
            case .signature:
                return 10
            case .encryptedData:
                return 5
            case .identityId:
                return 1
            }
        }
        
    }
    
    struct Constants {
        static let pairingDataKey = "_pd"
    }
}

