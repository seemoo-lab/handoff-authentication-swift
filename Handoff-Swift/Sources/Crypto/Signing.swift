//
//  SigningHandler.swift
//  ContinuityTests
//
//  Created by Alexander Heinrich on 18.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//


struct Signing {
    static let signatureLength: UInt64 = 64
    
    
    /// Sign given data using ed25519 curve signature
    ///
    /// - Parameters:
    ///   - message: Message data that should be signed
    ///   - pk: ed25519 public key
    ///   - sk: ed25519 secret key
    /// - Returns: A generated signature for the given message
    static func signWithEd25519(message: Data, pk: Data, sk: Data) -> Data {
        var secretKey = Array(sk)
        var publicKey = Array(pk)
        
        var messageArray = Array(message)
        
        //Sign the message
        var signature = Array<UInt8>(repeating: 0, count: Int(signatureLength))
        
        cced25519_sign_compat(&signature, &messageArray, messageArray.count, &publicKey, &secretKey)
        
        //Transform to data
        let signatureData = Data(signature)
        return signatureData
    }
    
    
    /// Verify a ED 25519 Signature with a given public key
    ///
    /// - Parameters:
    ///   - signature: The signature bytes
    ///   - message: Message without signature encoded as data
    ///   - pk: Public ed25519 Key bytes
    /// - Returns: true if the signature is correct
    static func verifyEd25519Signature(signature: Data, message: Data, pk: Data) -> Bool {
        var publicKey = Array(pk)
        
        var messageArray = Array(message)
        
        //Sign the message
        var signatureArray = Array<UInt8>(signature)
        
        //Verify the signature
        let verified = cced25519_verify_compat(&messageArray, messageArray.count, &signatureArray, &publicKey)
        
    
        return verified == 0
    }
}
