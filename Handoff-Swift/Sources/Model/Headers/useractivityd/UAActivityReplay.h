//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UACornerActionManagerHandler.h"

#import "NSNetServiceDelegate.h"
#import "SFActivityAdvertiserDelegate.h"
#import "SFActivityScannerDelegate.h"

@class NSMutableDictionary, NSObject<OS_dispatch_queue>, NSString, SFPeerDevice, UAActivityReplayAdvertiser, UAActivityReplayReceiver, UAMockActivityAdvertiser, UAMockActivityScanner, UAReplayClientController;

@interface UAActivityReplay : UACornerActionManagerHandler <NSNetServiceDelegate, SFActivityAdvertiserDelegate, SFActivityScannerDelegate>
{
    NSMutableDictionary *_pendingPayloadFetches;
    NSObject<OS_dispatch_queue> *_queue;
    SFPeerDevice *_pairedPeer;
    UAActivityReplayAdvertiser *_advertiser;
    UAActivityReplayReceiver *_receiver;
    UAReplayClientController *_client;
    UAMockActivityAdvertiser *_mockAdvertiser;
    UAMockActivityScanner *_mockScanner;
    NSMutableDictionary *_items;
}

@property(retain) NSMutableDictionary *items; // @synthesize items=_items;
@property(readonly, retain) UAMockActivityScanner *mockScanner; // @synthesize mockScanner=_mockScanner;
@property(readonly, retain) UAMockActivityAdvertiser *mockAdvertiser; // @synthesize mockAdvertiser=_mockAdvertiser;
@property(retain) UAReplayClientController *client; // @synthesize client=_client;
@property(retain) UAActivityReplayReceiver *receiver; // @synthesize receiver=_receiver;
@property(retain) UAActivityReplayAdvertiser *advertiser; // @synthesize advertiser=_advertiser;
@property(retain) SFPeerDevice *pairedPeer; // @synthesize pairedPeer=_pairedPeer;
@property(readonly, retain) NSObject<OS_dispatch_queue> *queue; // @synthesize queue=_queue;
- (void).cxx_destruct;
- (BOOL)terminate;
- (void)activityPayloadFromDevice:(id)arg1 forAdvertisementPayload:(id)arg2 command:(id)arg3 timeout:(unsigned long long)arg4 withCompletionHandler:(CDUnknownBlockType)arg5;
- (void)activityAdvertiser:(id)arg1 activityPayloadForAdvertisementPayload:(id)arg2 command:(id)arg3 requestedByDevice:(id)arg4 withCompletionHandler:(CDUnknownBlockType)arg5;
- (BOOL)processCommands:(id)arg1 completionHandler:(CDUnknownBlockType)arg2;
- (BOOL)sendResponse:(id)arg1;
- (BOOL)processCommand:(id)arg1;
- (id)scanMockAdvertisement:(id)arg1;
- (void)doAdvertiseAdvertisementPayload:(id)arg1 options:(id)arg2;
- (id)sharingAdvertiser;
- (id)sharingReceiver;
- (void)dealloc;
- (id)initWithManager:(id)arg1 name:(id)arg2;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

