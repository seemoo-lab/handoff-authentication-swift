//
//  PairingConfig.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 03.07.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

struct PairingConfig {
    var signingKeys: SigningKeys
    var pairingIdentity: String
    
    
    struct Static {
        
        /// Copied from a macOS Catalina Beta instance
        static var `default`: PairingConfig {
            let signingKeys = SigningKeys.Static.catalinaKeys
            let pairingID = "5F1BF65A-0633-4608-8E8D-CF40967F12CF"
            
            return PairingConfig(signingKeys: signingKeys, pairingIdentity: pairingID)
        }
        
        
        /// Alternative Pairing Config copied from my main macOS instance (Mojave)
        static var alternative: PairingConfig {
            let signingKeys = SigningKeys.Static.keys
            let pairingID = "5F1BF65A-0633-4608-8E8D-CF40967F12CF"
            
            return PairingConfig(signingKeys: signingKeys, pairingIdentity: pairingID)
        }
        
        static var eve: PairingConfig {
            let signingKeys = SigningKeys.Static.eveKeys
            let pairingId = "43B40D1F-60F2-45E3-838A-209204F865AC"
            
            return PairingConfig(signingKeys: signingKeys, pairingIdentity: pairingId)
        }
        
        
        /// Those keys are not listed in an Apple security access group (com.apple.rapport)
        static var evesBrother: PairingConfig {
            let signingKeys = SigningKeys.Static.evesBrotherKeys
            let pairingId = "43B40D1F-60F2-45E3-838A-209204F865AC"
            
            return PairingConfig(signingKeys: signingKeys, pairingIdentity: pairingId)
        }
    }
}
