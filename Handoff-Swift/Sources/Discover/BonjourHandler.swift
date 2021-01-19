//
//  BonjourHandler.swift
//  Handoff-Swift
//
//  Created by Alexander Heinrich on 12.06.19.
//  Copyright © 2019 Alexander Heinrich. All rights reserved.
//

import Foundation

protocol BonjourBrowserDelegate {
    func browserDidFind(browser: BonjourBrowser, service: BonjourService)
}

struct BonjourService {
    var domain: String
    var addresses: [Data]?
    var includesPeerToPeer: Bool
    var txtRecord: [String: Data]
    var name: String
    var type: String
    var port: Int
    var hostname: String?
    var ipAddresses: [String]?
}

#if !os(Linux)
class BonjourBrowser: NSObject {
    var delegate: BonjourBrowserDelegate?
    private var services: [NetService] = Array()
    private var browser: NetServiceBrowser?
    
    func searchForHandoff() {
        self.searchForHandoffMac()
    }
    
    private func searchForHandoffMac() {
        log("Starting Bonjour Discovery")
        
        let browser = NetServiceBrowser()
        browser.delegate = self
        //Use this to search on AWDL
        browser.includesPeerToPeer = true
        browser.searchForServices(ofType: "_companion-link._tcp.", inDomain: "local.")
        self.browser = browser
        withExtendedLifetime((browser, self), {
            RunLoop.main.run()
        })
    }
    
    /// Stop all currently running searches
    func stop() {
        self.browser?.stop()
        self.browser?.remove(from: RunLoop.main, forMode: .common)
        self.browser = nil 
        
    }
}

extension BonjourBrowser: NetServiceDelegate {
    func netServiceDidResolveAddress(_ sender: NetService) {
        log("Resolved addresses for service \(sender.name)")
        
        let service = sender
        
        var txtDictionary = [String : Data]()
        if let txtData = service.txtRecordData() {
            txtDictionary = NetService.dictionary(fromTXTRecord: txtData)
        }
        
        
        let bService = BonjourService(domain: service.domain, addresses: service.addresses, includesPeerToPeer: service.includesPeerToPeer, txtRecord: txtDictionary, name: service.name, type: service.type, port: service.port, hostname: service.hostName, ipAddresses: service.addresses?.map({self.binaryAddressToStringAddress(data: $0)}))
        
        DispatchQueue.main.async {
            self.delegate?.browserDidFind(browser: self, service: bService)
        }
    }
    
    func netService(_ sender: NetService, didNotResolve errorDict: [String : NSNumber]) {
        log("Failed resolving service \(sender.name)")
    }
    
    func netServiceDidPublish(_ sender: NetService) {
        log("Service did publish \(sender.name)")
    }
    
    func netServiceWillResolve(_ sender: NetService) {
        log("Service will resolve \(sender.name)")
    }
    
    func netService(_ sender: NetService, didUpdateTXTRecord data: Data) {
        log("Service did update txt record \(sender.name)")
    }
    
    func netServiceWillPublish(_ sender: NetService) {
        log("Service will publish \(sender.name)")
    }
    
    func netService(_ sender: NetService, didNotPublish errorDict: [String : NSNumber]) {
        log("Service did NOT publish \(sender.name)")
    }
    
    func netServiceDidStop(_ sender: NetService) {

    }
}

extension BonjourBrowser: NetServiceBrowserDelegate {
    func netServiceBrowserWillSearch(_ browser: NetServiceBrowser) {
        
    }
    
    func netServiceBrowserDidStopSearch(_ browser: NetServiceBrowser) {
        
    }
    
    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String : NSNumber]) {
        
    }
    
    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        log("Found service \(service.name)")
        service.delegate = self
        service.resolve(withTimeout: 10.0)
        self.services.append(service)
    }
    
    func netServiceBrowser(_ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool) {
        
    }
    
    func netServiceBrowser(_ browser: NetServiceBrowser, didFindDomain domainString: String, moreComing: Bool) {
        
    }
    
    func netServiceBrowser(_ browser: NetServiceBrowser, didRemoveDomain domainString: String, moreComing: Bool) {
        
    }
}
#endif

//Shared code
extension BonjourBrowser {
    func binaryAddressToStringAddress(data: Data) -> String {
        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        
        data.withUnsafeBytes { ptr in
            guard let sockaddr_ptr = ptr.baseAddress?.assumingMemoryBound(to: sockaddr.self) else {
                // handle error
                return
            }
            var sockaddr = sockaddr_ptr.pointee
            guard getnameinfo(sockaddr_ptr, socklen_t(sockaddr.sa_len), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 else {
                return
            }
        }
        let ipAddress = String(cString:hostname)
        
        return ipAddress
    }
}

#if os(Linux)
class BonjourBrowser {
    var delegate: BonjourBrowserDelegate
    
    func searchForHandoff() {
        fatalError("Not implemented")
    }
    
}
#endif
