//
//  Endianess.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 11.07.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

extension Data {
    func toBigEndian() -> Data {
        return Data(toBigEndianArray())
    }
    
    func toBigEndianArray() -> Array<UInt8> {
        return Array(self).reversed()
    }
}
