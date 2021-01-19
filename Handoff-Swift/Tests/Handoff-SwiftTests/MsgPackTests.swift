//
//  MsgPackTests.swift
//  ContinuityTests
//
//  Created by Alexander Heinrich on 06.08.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import XCTest

class MsgPackTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testReadFirstServerMessage() throws {
        let path = Bundle(for: MsgPackTests.self).path(forResource: "1_$server", ofType: "msgpack")!
        var data = try Data(contentsOf: URL(fileURLWithPath: path))
        var trimmedData = Data()
        
        var decoded = [AnyHashable: Any]()
        while true {
            do {
//                decoded = try MessagePackCoding.decode(fromData: data)
                break
            }catch {
                trimmedData.append(data[0])
                data = Data(data[1...])
            }
            
        }
        
        print("Decoded the packet from message pack. Trimmed \(trimmedData.count) bytes from header")
        XCTAssertNotNil(decoded)
        XCTAssertGreaterThan(decoded.keys.count, 0)
        print(decoded)
        
        //Decode the binary plist
        guard let plistDataString = decoded["data"] as? String,
             let plistData = Data(base64Encoded: plistDataString)
            else {
                XCTFail("Deserializing Data failed")
                return
        }
        
        //Write plist to file
        var plistPathURL = URL(fileURLWithPath: "/Users/Alex/Documents/Master Thesis/code/Handoff-Swift/Tests/Handoff-SwiftTests/Resources").appendingPathComponent("1_server_data.plist")
        try plistData.write(to: plistPathURL)
        
        //Transform to dict
        
    }

}
