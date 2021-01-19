//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UAReceiver.h"

@class NSArray, UASimulator;

@interface UASimulatorReceiver : UAReceiver
{
    UASimulator *_simulator;
    NSArray *_receivedItems;
}

@property(readonly, copy) NSArray *receivedItems; // @synthesize receivedItems=_receivedItems;
@property(readonly, retain) UASimulator *simulator; // @synthesize simulator=_simulator;
- (void).cxx_destruct;
- (id)statusString;
- (BOOL)active;
- (BOOL)fetchAdvertisedItems:(BOOL)arg1;
- (BOOL)doSetReceivedItems:(id)arg1;
- (id)initWithSimulator:(id)arg1;

@end

