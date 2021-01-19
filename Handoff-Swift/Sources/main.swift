//
//  main.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 28.05.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

if (sodium_init() < 0) {
    fatalError("initialization failed")
}

class Main:HandoffDelegate {

    
    func run() {
        do {
            
//            try MacKeychainController.createNewRPIdentityItem()
            //Attack!
//            let handoff = MalicousHandoff()
            //Normal!
            let handoff = Handoff()
            handoff.delegate = self
            handoff.run()
        }catch let error {
            print(error)
            exit(0)
        }

    }
    
    func didFinishPairing(withPairingSession pairingSession: PairingSession) {
            
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            do {
                var clipboardController = try UniversalClipboardController(withPairingSession: pairingSession, mode: .client)
                try clipboardController.requestSystemInfo()
             }catch let error {
                print(error)
                exit(0)
            }
        }
            
       
    }
    
    
}


Main().run()
