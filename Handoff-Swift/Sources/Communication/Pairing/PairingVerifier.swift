//
//  PairingVerifier.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 24.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

struct PairingVerifier {
    var publicKey: Data
    var peerPublicKey: Data
    
    func verifySignatureFromPeer(_ signature: Data) throws -> PairingIdentity {
        //Construct the signed data
        var message = peerPublicKey
        message.append(publicKey)
        
        //Verify that the signed data matches the signature
        let pairingIdentities = try PairingVerifier.loadPairingIdentitiesFromKeychain()
        
        for (_, pIdentity) in pairingIdentities {
            let edPubKey = pIdentity.value.edPublicKey
            
            let verified = Signing.verifyEd25519Signature(signature: signature, message: message, pk: edPubKey)
            
            if verified {
                return pIdentity
            }
        }
        
        throw VerificationError.noMatchingPairingIdentityFound
    }
    
    static func loadPairingIdentities() -> [String: PairingIdentity]?  {
        let currentDirectory = FileManager.default.currentDirectoryPath
        var url = URL(fileURLWithPath: currentDirectory)
        url.appendPathComponent("rp-identities.plist")
        
        
        do {
            let plistData: Data = try {
                if FileManager.default.fileExists(atPath: url.path) {
                    return try Data(contentsOf: url)
                }else {
                    return StaticFallback.pairingIdentitiesPlist.data(using: .utf8)!
                }
            }()
            
            let decoder = PropertyListDecoder()
            let pairingIdentities = try decoder.decode([String: PairingIdentity].self, from: plistData)
            return pairingIdentities
        }catch let error {
            log(error)
        }
        
        return nil
    }
    
    static func loadPairingIdentitiesFromKeychain() throws -> [String: PairingIdentity] {
        let service = "RPIdentity-SameAccountDevice"
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        var result = [String: PairingIdentity]()
        
        if status == errSecItemNotFound {
            print("Could not retrieve key")
            throw KeychainError.noItemFound(name: service)
        }else if let array = item as? [[String: Any]] {
//            print("Found \(array.count) items")
            //Query for each item
            try array.forEach { (attributes) in
                
                let allAttributes = try queryCurveKeys(forAttributes: attributes)
//                print(allAttributes)
                
                guard allAttributes[kSecAttrGeneric as String] != nil else {return}
                
                var value: [String : Any] = [
                    kSecAttrService as String: allAttributes[kSecAttrService as String] as! String,
                    kSecAttrLabel as String: allAttributes[kSecAttrLabel as String] as! String,
                    kSecAttrSynchronizable as String:  allAttributes[kSecAttrSynchronizable as String] as! Int,
                    kSecAttrGeneric as String: allAttributes[kSecAttrGeneric as String] as! Data,
                    kSecAttrAccount as String: allAttributes[kSecAttrAccount as String] as! String,
                ]
                
                var generalData: PairingIdentity.GeneralData?
                if let general = allAttributes[kSecAttrGeneric as String] as? Data {
                    let decoded = try OPACKCoding.decode(fromData: general)
//                    print("General information \(decoded)")
                    value[kSecAttrGeneric as String] = decoded
                    generalData = PairingIdentity.GeneralData(model: decoded["model"] as! String, ff: decoded["ff"] as? Int)
                }
                
                var valueDataStruct: PairingIdentity.ValueData?
                if let valueData = allAttributes[kSecValueData as String] as? Data {
                    let decoded = try OPACKCoding.decode(fromData: valueData)
//                    print("Value data \(decoded)")
                    value[kSecValueData as String]  = decoded
                    valueDataStruct = PairingIdentity.ValueData(bluetoothIRK: decoded["dIRK"] as! Data, edPublicKey: decoded["edPK"] as! Data)
                }
                
                if let generalData = generalData,
                   let valueData = valueDataStruct {
                    
                    let pairingIdentity = PairingIdentity(
                        id: attributes[kSecAttrAccount as String] as! String,
                        label: value[kSecAttrLabel as String] as! String,
                        synchronizable: (value[kSecAttrSynchronizable as String] as! Int) == 1,
                        general: generalData, value: valueData)
                    
                    result[attributes[kSecAttrAccount as String] as! String] = pairingIdentity
                }
                
            }
            
            return result
        }
        
        throw  KeychainError.noItemFound(name: service)
    }
        
        
    
    /// Query the value data of a SecKeychainItem described by attributes
    ///
    /// - Parameter attributes: Attributes that describe the SecKeyChainItem that should be queries
    /// - Returns: A dictionary that contains the kSecValueData and the item's attributes
    /// - Throws: KeychainError if fails
    static func queryCurveKeys(forAttributes attributes: [String: Any]) throws -> [String: Any] {
        let query : [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: attributes[kSecAttrService as String]!,
            kSecAttrAccount as String: attributes[kSecAttrAccount as String]!,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecReturnData as String: true,
            kSecReturnAttributes as String: true
        ]
        
        
        var itemWithData: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &itemWithData)
        
        guard status != errSecItemNotFound,
              let dict = itemWithData as? [String: Any]
        else {throw KeychainError.noItemFound(name: query[kSecAttrLabel as String] as! String)}
        
        return dict
    }
    
    enum VerificationError: Error {
        case noPairingIdentitiesFound
        case noMatchingPairingIdentityFound
    }
    
    enum KeychainError: Error {
        case keyExtractionFailed
        case noItemFound(name: String)
        case noKeysFound
        case unknown
    }
}

struct PairingIdentity: Codable {

    
    let id: String
    let label: String
    let synchronizable: Bool
    let general: GeneralData
    let value: ValueData
    
    enum CodingKeys: String, CodingKey {
        case id = "acct"
        case label = "labl"
        case synchronizable = "sync"
        case general = "gena"
        case value = "v_Data"
    }

    internal init(id: String, label: String, synchronizable: Bool, general: PairingIdentity.GeneralData, value: PairingIdentity.ValueData) {
        self.id = id
        self.label = label
        self.synchronizable = synchronizable
        self.general = general
        self.value = value
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        label = try container.decode(String.self, forKey: .label)
        synchronizable = try container.decode(Int.self, forKey: .synchronizable) == 1
        general = try container.decode(GeneralData.self, forKey: .general)
        value = try container.decode(ValueData.self, forKey: .value)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(label, forKey: .label)
        try container.encode(general, forKey: .general)
        try container.encode(synchronizable ? 1 : 0, forKey: .synchronizable)
        try container.encode(value, forKey: .value)
    }
    
    struct GeneralData: Codable {
        internal init(model: String, ff: Int?) {
            self.model = model
            self.ff = ff
        }
        
        let model: String
        let ff: Int?
    }
    
    struct ValueData: Codable {

        
        let bluetoothIRK: Data
        let edPublicKey: Data
        
        enum CodingKeys: String, CodingKey {
            case bIRK = "dIRK"
            case edPublicKey = "edPK"
        }
        
        
        
        func encode(to encoder: Encoder) throws {
            var container  = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(edPublicKey, forKey: .edPublicKey)
            try container.encode(bluetoothIRK, forKey: .bIRK)
        }
        
        internal init(bluetoothIRK: Data, edPublicKey: Data) {
            self.bluetoothIRK = bluetoothIRK
            self.edPublicKey = edPublicKey
        }
        
        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            edPublicKey = try container.decode(Data.self, forKey: .edPublicKey)
            bluetoothIRK = try container.decode(Data.self, forKey: .bIRK)
        }
    }
}


extension PairingVerifier {
    struct StaticFallback {
        static let pairingIdentitiesPlist =
        #"""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>048879B4-BD39-45BD-8BB3-AFA6272420BA</key>
            <dict>
                <key>acct</key>
                <string>048879B4-BD39-45BD-8BB3-AFA6272420BA</string>
                <key>gena</key>
                <dict>
                    <key>model</key>
                    <string>MacBookAir6,2</string>
                </dict>
                <key>labl</key>
                <string>Alexander’s MacBook Air</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>0</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    a0ppSECK2LQe2GUqyCgogw==
                    </data>
                    <key>edPK</key>
                    <data>
                    0+OYL0S/YNsYdWfRpV6voy8pC2FatYxJ5crW+AdXH68=
                    </data>
                </dict>
            </dict>
            <key>171C1ABC-EEF5-4DA0-BF48-727A9AEFABF6</key>
            <dict>
                <key>acct</key>
                <string>171C1ABC-EEF5-4DA0-BF48-727A9AEFABF6</string>
                <key>gena</key>
                <dict>
                    <key>ff</key>
                    <integer>3</integer>
                    <key>model</key>
                    <string>iPhone10,6</string>
                </dict>
                <key>labl</key>
                <string>iPhone</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>1</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    STUH03vh8kNdNAr39TkYRw==
                    </data>
                    <key>edPK</key>
                    <data>
                    Ao4gv5E+cjeByxVfRSYcLPFgYKS7xJCdoAwuYcsCJeE=
                    </data>
                </dict>
            </dict>
            <key>5051C32E-1209-4ADF-84E5-8B34467B95C1</key>
            <dict>
                <key>acct</key>
                <string>5051C32E-1209-4ADF-84E5-8B34467B95C1</string>
                <key>gena</key>
                <dict>
                    <key>model</key>
                    <string>AppleTV5,3</string>
                </dict>
                <key>labl</key>
                <string>Wohnzimmer</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>0</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    DuhbvTIAGQYuqJ9po03CBg==
                    </data>
                    <key>edPK</key>
                    <data>
                    56h/nd5U3VbpWJS2iS+fj8dpiIRx8Yi/aU3aINC0Ifw=
                    </data>
                </dict>
            </dict>
            <key>5F1BF65A-0633-4608-8E8D-CF40967F12CF</key>
            <dict>
                <key>acct</key>
                <string>5F1BF65A-0633-4608-8E8D-CF40967F12CF</string>
                <key>gena</key>
                <dict>
                    <key>ff</key>
                    <integer>3</integer>
                    <key>model</key>
                    <string>MacBookPro11,5</string>
                </dict>
                <key>labl</key>
                <string>Alexander’s MacBook Pro</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>1</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    6U6ldvdRnV0bn4BwVwj7ZQ==
                    </data>
                    <key>edPK</key>
                    <data>
                    SiKpmX0AcgZeOCWLjTvFJK3W/A4Tgv4JenBSjE7MJDY=
                    </data>
                </dict>
            </dict>
            <key>64E5D672-3B41-427A-BDEA-511D01F9C5CA</key>
            <dict>
                <key>acct</key>
                <string>64E5D672-3B41-427A-BDEA-511D01F9C5CA</string>
                <key>gena</key>
                <dict>
                    <key>ff</key>
                    <integer>3</integer>
                    <key>model</key>
                    <string>iPad6,3</string>
                </dict>
                <key>labl</key>
                <string>Alexanders iPad (2)</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>1</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    HhmDRIg/Bv0mYOzi7GgDpg==
                    </data>
                    <key>edPK</key>
                    <data>
                    49l64M3PjPcHwIbjsPxrZNq3kbNSW5G5QbaGWzLPDnk=
                    </data>
                </dict>
            </dict>
            <key>68800C7B-BBD4-47CF-BBFD-10C59232002D</key>
            <dict>
                <key>acct</key>
                <string>68800C7B-BBD4-47CF-BBFD-10C59232002D</string>
                <key>gena</key>
                <dict>
                    <key>ff</key>
                    <integer>3</integer>
                    <key>model</key>
                    <string>MacBookPro11,5</string>
                </dict>
                <key>labl</key>
                <string>Alexander’s MacBook Pro</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>1</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    Atbjq7DfFkuJsYAgcl7s8w==
                    </data>
                    <key>edPK</key>
                    <data>
                    5XmKpBCeH1pQtv3CtwEvZkIqJgKKn7W+9I0fYlc7Zs8=
                    </data>
                </dict>
            </dict>
            <key>8EFCF9EB-D39E-4070-BD4A-93389BA8C00B</key>
            <dict>
                <key>acct</key>
                <string>8EFCF9EB-D39E-4070-BD4A-93389BA8C00B</string>
                <key>gena</key>
                <dict>
                    <key>ff</key>
                    <integer>3</integer>
                    <key>model</key>
                    <string>iPhone8,1</string>
                </dict>
                <key>labl</key>
                <string>Alex SFD iPhone 6</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>1</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    1kZOcWkW2WgnxdSSLccCLg==
                    </data>
                    <key>edPK</key>
                    <data>
                    Zh+i1bVww3qFfqkbOUkPGSdps5TvwfnoetEaVWMhJr4=
                    </data>
                </dict>
            </dict>
            <key>968B4D82-751E-414F-8B96-76364F294803</key>
            <dict>
                <key>acct</key>
                <string>968B4D82-751E-414F-8B96-76364F294803</string>
                <key>gena</key>
                <dict>
                    <key>ff</key>
                    <integer>3</integer>
                    <key>model</key>
                    <string>iPad6,3</string>
                </dict>
                <key>labl</key>
                <string>iPad</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>1</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    855LiwWZLgTe1fgiKXcvhQ==
                    </data>
                    <key>edPK</key>
                    <data>
                    mF9y3sVHiwSY/8+pKM0yj4lPranKis5NVgCtFqLPBpw=
                    </data>
                </dict>
            </dict>
            <key>A5AC9527-3277-4A71-A2AA-871B00226BB8</key>
            <dict>
                <key>acct</key>
                <string>A5AC9527-3277-4A71-A2AA-871B00226BB8</string>
                <key>gena</key>
                <dict>
                    <key>ff</key>
                    <integer>3</integer>
                    <key>model</key>
                    <string>iPhone10,6</string>
                </dict>
                <key>labl</key>
                <string>Alex‘ iPhone</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>1</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    N468OpnPgySB+L567sAZnQ==
                    </data>
                    <key>edPK</key>
                    <data>
                    6PqBS3uL1Sk1a9DgrvVbMSN0mOEak+wvBw1RvJh9Z+E=
                    </data>
                </dict>
            </dict>
            <key>D12BA2B9-0449-4021-8081-646D26447496</key>
            <dict>
                <key>acct</key>
                <string>D12BA2B9-0449-4021-8081-646D26447496</string>
                <key>gena</key>
                <dict>
                    <key>model</key>
                    <string>Watch3,2</string>
                </dict>
                <key>labl</key>
                <string>Alexander sin Apple Watch</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>0</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    hMANsWxZIUrX0unUIsdVMw==
                    </data>
                    <key>edPK</key>
                    <data>
                    B3LIStX7jtn7WFP9kstufpAuv9cFVFNLwMPjEdytw4c=
                    </data>
                </dict>
            </dict>
            <key>E005608B-90BC-4730-BF8C-19AB0BAB37F5</key>
            <dict>
                <key>acct</key>
                <string>E005608B-90BC-4730-BF8C-19AB0BAB37F5</string>
                <key>gena</key>
                <dict>
                    <key>ff</key>
                    <integer>3</integer>
                    <key>model</key>
                    <string>iMac13,2</string>
                </dict>
                <key>labl</key>
                <string>SEEMOOs iMac</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>1</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    Pbb3uokUfi8ekonXDMa6cw==
                    </data>
                    <key>edPK</key>
                    <data>
                    yosbRSpsdUItp+u9RHO02pbEHx/J/nwnfoe7JorEVsk=
                    </data>
                </dict>
            </dict>
            <key>F7CA5511-FBE2-4C27-8C5F-D1BDAC1636D7</key>
            <dict>
                <key>acct</key>
                <string>F7CA5511-FBE2-4C27-8C5F-D1BDAC1636D7</string>
                <key>gena</key>
                <dict>
                    <key>model</key>
                    <string>iPad8,5</string>
                </dict>
                <key>labl</key>
                <string>Alexanders iPad</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>0</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    lXCvAu/41grcdCoCxfByzQ==
                    </data>
                    <key>edPK</key>
                    <data>
                    8+vaVA1U5cN99ouCa/CWTcVNMQ2S5+p9+RPpXqy3HYY=
                    </data>
                </dict>
            </dict>
            <key>F9C94AEA-157D-48F1-8EA4-54B86D49951B</key>
            <dict>
                <key>acct</key>
                <string>F9C94AEA-157D-48F1-8EA4-54B86D49951B</string>
                <key>gena</key>
                <dict>
                    <key>ff</key>
                    <integer>3</integer>
                    <key>model</key>
                    <string>iPhone10,6</string>
                </dict>
                <key>labl</key>
                <string>iPhone</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>1</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    15uemdVYV+nrWPUHNuueEg==
                    </data>
                    <key>edPK</key>
                    <data>
                    l2jHEG6YgFcnSskCN60pqvRyd5TgqRufAYPHgTWYT5E=
                    </data>
                </dict>
            </dict>
            <key>FCEA3D9A-9758-47FE-82E8-2F187D096951</key>
            <dict>
                <key>acct</key>
                <string>FCEA3D9A-9758-47FE-82E8-2F187D096951</string>
                <key>gena</key>
                <dict>
                    <key>model</key>
                    <string>Watch3,2</string>
                </dict>
                <key>labl</key>
                <string>Alexander sin Apple Watch</string>
                <key>svce</key>
                <string>RPIdentity-SameAccountDevice</string>
                <key>sync</key>
                <integer>0</integer>
                <key>v_Data</key>
                <dict>
                    <key>dIRK</key>
                    <data>
                    bg9n0o8VGeU9/Jb7hrVDSw==
                    </data>
                    <key>edPK</key>
                    <data>
                    w/ZZBrSb1NkNn9b2sendTk2E1qkAI8YoKY46KHHRqwI=
                    </data>
                </dict>
            </dict>
        </dict>
        </plist>

        """#
    }
}
