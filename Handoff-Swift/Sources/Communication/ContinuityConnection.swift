//
//  ContinuityConnection.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 17.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation
import NIO
import Socket

protocol ConnectionDelegate {
    func receivedData(_ data: Data)
    func receivedPacket(_ packet: ContinuityPacket)
}

class ContinuityConnection {
    let service: BonjourService?
    let hostAddress: String
    let hostPort: Int
    
    var delegate: ConnectionDelegate? {
        didSet {
            self.connectionHandler?.delegate = self.delegate
        }
    }
    
    /// Handles incoming / outgoing events
    private var group: MultiThreadedEventLoopGroup!
    /// Handles connections
    private var bootstrap:  ClientBootstrap!
    /// If connection is active the channel has a value
    private var channel: Channel?
    
    private var connectionHandler: ConnectionHandler?
    
    init(withService service: BonjourService) throws {
        //Check if IP address points to an AWDL inteface
        guard let address = service.ipAddresses?.first
            else {throw ConnectionError.noAddressFound}
        self.service = service
        self.hostAddress = address
        self.hostPort = service.port
    }
    
    
    /// Connect to the peer that has been used during intialization
    ///
    /// - Throws: When the connection fails
    func connect() throws {
        self.connectionHandler = ConnectionHandler(delegate: self.delegate)
        
        group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        bootstrap = ClientBootstrap(group: group)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), 0x1104), value: 1)
        .channelInitializer({ (channel) -> EventLoopFuture<Void> in
                channel.pipeline.addHandler(self.connectionHandler!)
            })


        let address = try SocketAddress(ipAddress: self.hostAddress, port: self.hostPort)
        channel = try bootstrap.connect(to: address).wait()
//        channel = try bootstrap.connect(host: self.hostAddress, port: self.hostPort).wait()
    }
    
    
    
    /// Send a data packet to the peer
    ///
    /// - Parameter data: Data that should be sent
    /// - Throws: when the sending fails or the channel cannot be allocated 
    func sendPacket(withData data: Data) throws {
        guard var buffer = self.channel?.allocator.buffer(capacity: data.count) else {
            throw ConnectionError.channelAllocationFailed
        }

        log("Sending packet \(data.hexadecimal)")
        
        
        data.withUnsafeBytes { (unsafeRawBufferPointer) -> Void in
            buffer.writeBytes(unsafeRawBufferPointer)
        }

        try channel?.writeAndFlush(buffer).wait()
    
    }
    
    
    /// Send a packet that conforms to ContinuitySendable
    ///
    /// - Parameter packet: Packet that should be sent
    /// - Throws: when the sending fails or the channel cannot be allocated
    func send(packet: ContinuitySendable) throws {
       try self.sendPacket(withData: packet.data)
    }
    
    enum ConnectionError: Error {
        case notOnAWDL
        case channelAllocationFailed
        case noAddressFound
    }
}

extension ContinuityConnection {
    private final class ConnectionHandler: ChannelInboundHandler {
        var delegate: ConnectionDelegate?
        
        typealias InboundIn = ByteBuffer
        
        init(delegate: ConnectionDelegate? = nil) {
            self.delegate = delegate
        }
        
        private func printByte(_ byte: UInt8) {
            #if os(Android)
            print(Character(UnicodeScalar(byte)),  terminator:"")
            #else
            fputc(Int32(byte), stdout)
            #endif
        }
        
        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            var buffer = self.unwrapInboundIn(data)
            
            var readData = Data()
            
            while let byte: UInt8 = buffer.readInteger() {
//                printByte(byte)
                readData.append(byte)
            }
            
            //Convert data to continuity packet
            DispatchQueue.main.async {
                do {
                    self.delegate?.receivedPacket(try ContinuityPacket(data: readData))
                }catch let error {
                    log("Parsing packet failed \(error)")
                    //Failed parsing. Send over data directly
                    self.delegate?.receivedData(readData)
                }
            }
           
        }
        
        func errorCaught(context: ChannelHandlerContext, error: Error) {
            log("Error caught \(error)", logLevel: .default)
        }
        
        func channelActive(context: ChannelHandlerContext) {
            log("Channel is active at port \(context.channel.localAddress?.port)")
        }
    }
}
