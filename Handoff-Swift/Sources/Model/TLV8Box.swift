//
//  TLV8Box.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 28.05.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

struct TLV8Box {
    var tlvs: [TLV8]
    
    init() {
        tlvs = []
    }
    
    init(tlvs: [TLV8]) {
        self.tlvs = tlvs
    }
    
    mutating func addValue(withType type: TLVType, andLength length: UInt8, andValue value: Data) {
        let tlv = TLV8(type: type.uInt8, length: length, value: value)
        
        self.tlvs.append(tlv)
    }
    
    mutating func addInt(withType type: TLVType, andValue value: UInt8) {
        var val = value
        let dataNum = Data(bytes: &val, count: MemoryLayout.size(ofValue: val))
        
        self.addValue(withType: type, andLength: UInt8(MemoryLayout.size(ofValue: value)), andValue: dataNum)
    }
    
    
    /// Get a normal dictionary from the TLV files
    ///
    /// - Returns: Dictionary with TLV types as index and the data value
    func toDictionary() -> [UInt8 : Data] {
        var dict = [UInt8 : Data]()
        
        tlvs.forEach({dict[$0.type] = $0.value})
        
        return dict
    }
    
    /// Serialize the TLV to a bytes buffer
    ///
    /// - Returns: Data containing the serialized TLV
    func serialize() throws -> Data {
        var serialized = Data()

        tlvs.forEach { (tlv) in
            serialized.append(contentsOf: [tlv.type, tlv.length])
            serialized.append(tlv.value)
        }
        
        return serialized
    }
    
    
    /// Get the TLV value for a specific type
    ///
    /// - Parameter type: a tlv type
    /// - Returns: The assigned value if one is assigned
    func getValue(forType type: TLVType) -> Data? {
        let tlv = tlvs.first(where: {$0.type == type.uInt8})
        
        return tlv?.value
    }
    
    func getTypes() -> [UInt8] {
        return tlvs.map({$0.type})
    }
 
    /// Deserialize a binary TLV8 to a TLV8Box struct.
    ///
    /// - Parameter data: that contains serialized TLV8
    /// - Returns: TLV8Box that contains all parsed TLVs
    /// - Throws: TLVError if parsing fails
    static func deserialize(fromData data: Data) throws -> TLV8Box {
        
        var index: Data.Index = data.startIndex
        var box = TLV8Box()
        
        //Iterate over the bytes until every TLV is parsed
        while index < data.endIndex {
            //Get type and length
            let type = data[index]
            index = index.advanced(by: 1)
            let length = data[index]
            index = index.advanced(by: 1)
            
            //Get the index of the
            let valueEndIndex = index.advanced(by: Int(length))
            
            guard valueEndIndex <= data.endIndex else {throw TLVError.parsingFailed}
            
            let value = data[index..<valueEndIndex]
            
            let tlv  = TLV8(type: type, length: length, value: value)
            box.tlvs.append(tlv)
            
            index = valueEndIndex
        }
        
        
        return box
    }

}


enum TLVError: Error {
    case serializationPointerFailed
    case parsingFailed
}

protocol TLVType {
    var uInt8: UInt8 { get }
}
