//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UAAdvertisableItem.h"

@class UASimulator;

@interface UASimulatorSuggestedItem : UAAdvertisableItem
{
    UASimulator *_simulator;
}

@property(retain) UASimulator *simulator; // @synthesize simulator=_simulator;
- (void).cxx_destruct;
- (void)clearPayload;
- (BOOL)wasResumedOnAnotherDeviceWithCompletionHandler:(CDUnknownBlockType)arg1;
- (BOOL)requestPayloadWithCompletionHandler:(CDUnknownBlockType)arg1;
- (id)initWithArchivedUserActivityInfo:(id)arg1 peerDevice:(id)arg2 simulator:(id)arg3;
- (id)initWithUserActivityInfo:(id)arg1 peerDevice:(id)arg2 simulator:(id)arg3;

@end

