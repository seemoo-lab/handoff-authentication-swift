//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class SFPeerDevice, UAPairedSFActivityAdvertiser;

@interface UAPairedSFActivityScanner : NSObject
{
    BOOL _sendFoundDevice;
    UAPairedSFActivityAdvertiser *_pairedAdvertiser;
    id <SFActivityScannerDelegate> _delegate;
    SFPeerDevice *_peer;
}

@property BOOL sendFoundDevice; // @synthesize sendFoundDevice=_sendFoundDevice;
@property(readonly, copy) SFPeerDevice *peer; // @synthesize peer=_peer;
@property id <SFActivityScannerDelegate> delegate; // @synthesize delegate=_delegate;
@property(retain) UAPairedSFActivityAdvertiser *pairedAdvertiser; // @synthesize pairedAdvertiser=_pairedAdvertiser;
- (void).cxx_destruct;
- (void)activityPayloadFromDevice:(id)arg1 forAdvertisementPayload:(id)arg2 command:(id)arg3 timeout:(unsigned long long)arg4 withCompletionHandler:(CDUnknownBlockType)arg5;
- (void)receiveAdvertisement:(id)arg1 options:(id)arg2 fromPeer:(id)arg3;
- (void)scanForTypes:(unsigned long long)arg1;
- (id)initWithDelegate:(id)arg1;

@end

