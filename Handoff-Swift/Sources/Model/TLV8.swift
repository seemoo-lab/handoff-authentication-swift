//
//  TLV8.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 28.05.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

struct TLV8 {
    let type: uint8
    let length: uint8
    let value: Data
}
