//
//  PairingDevice.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 12.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

#if os(macOS)
import Security
#endif

/// This class is responsible for using 
class PairingDevice {
    static let current = PairingDevice()
    
    var config: PairingConfig
    var signingKeys: SigningKeys {
        return config.signingKeys
    }
    
    
    
    init() {
        //Load the signing keys to verify the identity
        
        //Use some present signing Keys for testing
        self.config = PairingConfig.Static.alternative
        
        #if os(macOS)
//        self.loadSigningKeysFromKeychain()
        #else //Linux or other
        // Load the keys from file
        keys = SigningKeys.Static.keys
        #endif
    }
    
    
    #if os(macOS)
    /// The RPIdentitySelf key is stored in the iCloud keychain. This requires special entititlements to access it.
    /// Make sure to sign your Application with those entitlements and restart mac with amfi_get_out_of_my_way=0x1 and system integrety protection off
//    func loadSigningKeysFromKeychain() {
//        let query: [String: Any] = [
//            kSecClass as String: kSecClassGenericPassword,
//            kSecAttrService as String: "RPIdentity-Self",
//            kSecAttrAccount as String: "SelfIdentity",
//            kSecReturnAttributes as String: true,
//            kSecReturnData as String: true
//        ]
//        
//        var item: CFTypeRef?
//        let status = SecItemCopyMatching(query as CFDictionary, &item)
//        
//        if status == errSecItemNotFound {
//            //Use the static keys
//            self.signingKeys = SigningKeys.Static.keys
//            return
//        }else if let dict = item as? [AnyHashable: Any],
//            let valueData = dict[kSecValueData as String] as? Data,
//            let opackDecoded = try? OPACKCoding.decode(fromData: valueData),
//            let secretKey = opackDecoded["edSK"] as? Data,
//            let publicKey = opackDecoded["edPK"] as? Data {
//            
//            self.signingKeys = SigningKeys(edSecretKey: secretKey, edPublicKey: publicKey)
//            
//            return
//        }
//        
//        //Use static keys
//        self.signingKeys = SigningKeys.Static.keys
//        return
//    }
    #endif
    
}
