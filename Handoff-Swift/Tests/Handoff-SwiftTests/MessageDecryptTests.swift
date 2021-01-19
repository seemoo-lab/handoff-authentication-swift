//
//  MessageDecryptTests.swift
//  ContinuityTests
//
//  Created by Alexander Heinrich on 25.07.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import XCTest

class MessageDecryptTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testDecryptTcpTLS() throws {
        let packets = AWDLMesssages.tcp_tls_packets()
        let sharedSecret = "7d 5d 42 18 cb e5 de 72 47 e2 c8 b8 c4 2f e0 d6 47 72 b6 b3 29 d9 cb f2 c4 a3 b1 e4 82 4c 0e 78"
        
        let decryptor = MessageDecryptor(sharedSecret: sharedSecret, packets: packets)
        try decryptor.decrypt()
    }

}
