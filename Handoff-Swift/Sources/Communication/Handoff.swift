//
//  Handoff.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 04.07.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

protocol HandoffDelegate {
    func didFinishPairing(withPairingSession pairingSession: PairingSession)
}

class Handoff: BonjourBrowserDelegate {
    var delegate: HandoffDelegate? = nil
    var pairingSession: PairingSession?
    var sessionStarted = false
    
    func browserDidFind(browser: BonjourBrowser, service: BonjourService) {
        log("Did discover service: \(service)")
        
        
//        if /*service.ipAddresses!.contains(where: {$0.contains("%awdl")}) && */ service.hostname?.contains("Alexanders-MacBook-Pro") == true {
//            browser.stop()
//
//
//
//        }
        if sessionStarted == false {
            self.startPairingSession(withService: service)
            browser.stop()
            sessionStarted = true
        }
        
        
    }
    
    func startPairingSession(withService service: BonjourService) {
        //Let's go!
        do {
            log("Starting pairing session with \(service.name)", logLevel: .default)
            let ps = try PairingSession()
            ps.delegate = self
            self.pairingSession = ps
            try ps.connect(to: service)
            try ps.startKeyExchange()
            
        }catch let error {
            log("Error occurred during pairing session \(error)")
            exit(0)
        }
    }
    
    
    func run() {
        //Start Bonjour discovery for Handoff / Companion link
        let browser = BonjourBrowser()
        browser.delegate = self
        browser.searchForHandoff()
    }
}

extension Handoff: PairingSessionDelegate {
    func didFinishPairing(withPairingSession pairingSession: PairingSession) {
        self.delegate?.didFinishPairing(withPairingSession: pairingSession)
    }
    
    
}



enum HandoffError: Error {
    case noConnection
}
    
