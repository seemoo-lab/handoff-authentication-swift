//
//  Log.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 12.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

enum LogLevel: Int {
    case debug = 10
    case `default` = 5
    case none = 0
}

var currentLogLevel = LogLevel.debug

func log(_ items: Any...,separator: String = " ", logLevel: LogLevel = LogLevel.debug) {
    let output = items.map{ "*\($0)" }.joined(separator: separator)
    if currentLogLevel.rawValue >= logLevel.rawValue {
        Swift.print(output)
    }
}


