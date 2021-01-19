//
//  SessionKeys.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 12.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//


/// A struct that handles all the keys that are generated and used througout a pairing session
struct CurveKeyPair {
    var secretKey: Data
    var publicKey: Data
    
    var sharedSecret: Data?
    
    init(sKey: Data,pKey: Data ) {
        secretKey = sKey
        publicKey = pKey
    }
}
