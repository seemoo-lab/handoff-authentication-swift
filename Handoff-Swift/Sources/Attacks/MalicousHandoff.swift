//
//  MalicousHandoff.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 27.08.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

class MalicousHandoff: Handoff {
    
    override func startPairingSession(withService service: BonjourService) {
        do {
            log("Starting pairing session with \(service.name)", logLevel: .default)
            let ps = try MalicousPairingSession(attack: .malicousContinuityPacket)
            ps.delegate = self
            self.pairingSession = ps
            try ps.connect(to: service)
            try ps.startKeyExchange()
            
        }catch let error {
            log("Error occurred during pairing session \(error)")
            exit(0)
        }
    }
}
