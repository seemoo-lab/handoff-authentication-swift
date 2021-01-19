//
//  UASharedPasteboardInfo.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 01.07.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation
@objc(UASharedPasteboardInfoWrapper) class UASharedPasteboardInfoWrapper: NSObject, NSSecureCoding {
    
    var pbInfo: UASharedPasteboardInfo?
    var extraData: Data?
    var extraDataType: Int?
    var error: NSError?
    var protocolVersion: Int!
    
    required init?(coder aDecoder: NSCoder) {
        super.init()
        pbInfo = aDecoder.decodeObject(of: UASharedPasteboardInfo.self, forKey: Keys.pasteboardInfoKey.rawValue)
        extraData = aDecoder.decodeObject(of: NSData.self, forKey: Keys.extraDataKey.rawValue) as Data?
        extraDataType = aDecoder.decodeInteger(forKey: Keys.extraDataTypeKey.rawValue)
        error  = aDecoder.decodeObject(of: NSError.self, forKey: Keys.errorKey.rawValue)
        protocolVersion = aDecoder.decodeInteger(forKey: Keys.versionKey.rawValue)
        print(aDecoder.attributeKeys)
    }
    
    func encode(with aCoder: NSCoder) {}
    
    static var supportsSecureCoding: Bool {
        return true
    }
    
    enum Keys: String {
        case pasteboardInfoKey = "UASharedPasteboardInfoWrapperPBInfoKey"
        case extraDataKey = "UASharedPasteboardInfoWrapperExtraDataKey"
        case extraDataTypeKey = "UASharedPasteboardInfoWrapperExtraTypeKey"
        case errorKey = "UASharedPasteboardInfoWrapperErrorKey"
        case versionKey = "UASharedPasteboardInfoWrapperProtocolVersionKey"
    }
}

@objc(UASharedPasteboardInfo) class UASharedPasteboardInfo: NSObject, NSSecureCoding {
    var fileHandle: FileHandle?
    var dataSize: Int?
    var items: [UASharedPasteboardItemInfo]?
    var sharedDataPath: String?
    var sandboxExtensions: NSDictionary?
    
    required init?(coder aDecoder: NSCoder) {
        super.init()
        
        fileHandle = aDecoder.decodeObject(of: FileHandle.self, forKey: Keys.fileKey.rawValue)
        dataSize = aDecoder.decodeInteger(forKey: Keys.dataSizeKey.rawValue)
        items = aDecoder.decodeObject(of: [NSArray.self, UASharedPasteboardItemInfo.self], forKey: Keys.itemsKey.rawValue) as? [UASharedPasteboardItemInfo]
        sharedDataPath = aDecoder.decodeObject(of: NSString.self, forKey: Keys.dataPathKey.rawValue) as String?
        
        sandboxExtensions = aDecoder.decodeObject(of: [NSDictionary.self, NSString.self, NSData.self], forKey: Keys.sandboxExtensionsKey.rawValue) as? NSDictionary
        
    }
    
    func encode(with aCoder: NSCoder) {}
    
    
    static var supportsSecureCoding: Bool {
        return true
    }
    
    enum Keys: String {
        case fileKey = "UASharedPasteboardInfoDataFileKey"
        case dataSizeKey = "UASharedPasteboardInfoDataSizeKey"
        case itemsKey = "UASharedPasteboardInfoItemsKey"
        case dataPathKey = "UASharedPasteboardInfoDataPathKey"
        case sandboxExtensionsKey = "UASharedPasteboardInfoExtensionKey"
    }
    
}

@objc(UASharedPasteboardItemInfo) class UASharedPasteboardItemInfo: NSObject, NSSecureCoding {
    
    var types: NSDictionary?
    
    required init?(coder aDecoder: NSCoder) {
        super.init()
        types = aDecoder.decodeObject(of: [NSDictionary.self, NSString.self, UASharedPasteboardTypeInfo.self], forKey: Keys.infoTypesKey.rawValue) as? NSDictionary
    }
    
    func encode(with aCoder: NSCoder) {}
    
    static var supportsSecureCoding: Bool {
        return true
    }
    
    enum Keys: String {
        case infoTypesKey =  "UASharedPasteboardItemInfoTypesKey"
    }
}

@objc(UASharedPasteboardTypeInfo) class UASharedPasteboardTypeInfo: NSObject, NSSecureCoding {
    
    var type: String?
    var uuid: NSUUID?
    var offset: NSNumber?
    var size: Int?
    var dataFile: FileHandle?
    var index: NSNumber?
    
//    init(type: String, uuid: NSUUID, offset: NSNumber, size: Int, dataFile: FileHandle?, index: NSNumber) {
//
//    }
    
    required init?(coder aDecoder: NSCoder) {
        super.init()
        
        
        type = aDecoder.decodeObject(of: NSString.self, forKey: Keys.typeKey.rawValue) as String?
        uuid = aDecoder.decodeObject(of: NSUUID.self, forKey: Keys.uuidKey.rawValue) as NSUUID?
        offset = aDecoder.decodeObject(of: NSNumber.self, forKey: Keys.offsetKey.rawValue) as NSNumber?
        size = aDecoder.decodeInteger(forKey: Keys.sizeKey.rawValue)
        dataFile = aDecoder.decodeObject(of: FileHandle.self, forKey: Keys.fileKey.rawValue)
        index = aDecoder.decodeObject(of: NSNumber.self, forKey: Keys.indexKey.rawValue)
    }
    
    func encode(with aCoder: NSCoder) {}
    
    static var supportsSecureCoding: Bool {
        return true
    }
    
    override var description: String {
        return (
        """
        Type: \(type ?? "no type")
        uuid: \(uuid?.uuidString ?? "000")
        offset: \(String(describing: offset))
        size: \(String(describing: size))
        dataFile: \(String(describing: dataFile))
        index: \(String(describing: index))
        """
        )
    }
    
    enum Keys: String {
        case typeKey = "UASharedPasteboardTypeInfoTypeKey"
        case uuidKey = "UASharedPasteboardTypeInfoUUIDKey"
        case offsetKey = "UASharedPasteboardTypeInfoOffsetKey"
        case sizeKey = "UASharedPasteboardTypeInfoSizeKey"
        case fileKey = "UASharedPasteboardTypeInfoDataFileKey"
        case indexKey = "UASharedPasteboardTypeInfoIndex"
    }
}
