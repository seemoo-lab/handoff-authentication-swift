//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class SFActivityScanner, SFPeerDevice;

@interface UASharedPasteboardDataRequester : NSObject
{
    SFPeerDevice *_peer;
    SFActivityScanner *_scanner;
}

@property(retain) SFActivityScanner *scanner; // @synthesize scanner=_scanner;
@property(retain) SFPeerDevice *peer; // @synthesize peer=_peer;
- (void).cxx_destruct;
- (void)requestRemotePasteboardInfo:(CDUnknownBlockType)arg1;
- (void)requestStreamEndpointDataV2:(CDUnknownBlockType)arg1;
- (void)requestStreamEndpointData:(CDUnknownBlockType)arg1;

@end
