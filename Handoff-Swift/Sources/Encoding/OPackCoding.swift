//
//  OPackCoding.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 29.05.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation


/// This is a wrapper around Apple's OPACK Encoding functions
struct OPACKCoding {
    
    static func encode(fromDictionary dict: [AnyHashable: Any]) throws -> Data {
        var errorPointer: NSError? = nil
        let out: Data? =  OPACKEncoderCreateDataMutable(dict, 0, &errorPointer) as Data?
        
        guard let data = out,
            errorPointer == nil else {throw OPACKError.encodingFailed(errorPointer!)}
        
        return data
    }
    
    static func decode(fromData data: Data) throws -> [AnyHashable:Any] {
        var errorPointer: NSError? = nil
        let out = OPACKDecodeData(data, 8, &errorPointer)
        
        //Check if error not nil. Throw error if an error occurred
        guard let decodedDict = out,
            errorPointer == nil else {throw OPACKError.decodingFailed(errorPointer!)}
        
        return decodedDict
    }
    
}

enum OPACKError: Error {
    case encodingFailed(NSError)
    case decodingFailed(NSError)
}
