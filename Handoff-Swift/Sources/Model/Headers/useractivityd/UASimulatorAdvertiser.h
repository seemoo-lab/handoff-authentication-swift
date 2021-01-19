//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UAAdvertiser.h"

@class NSMutableArray, UASimulator;

@interface UASimulatorAdvertiser : UAAdvertiser
{
    NSMutableArray *_advertisableItems;
    UASimulator *_simulator;
}

@property(readonly, retain) UASimulator *simulator; // @synthesize simulator=_simulator;
- (void).cxx_destruct;
- (id)statusString;
- (BOOL)updateItem:(id)arg1;
- (id)advertisingItems;
- (void)setAdvertisableItems:(id)arg1;
- (id)advertisableItems;
- (id)initWithSimulator:(id)arg1;

@end

