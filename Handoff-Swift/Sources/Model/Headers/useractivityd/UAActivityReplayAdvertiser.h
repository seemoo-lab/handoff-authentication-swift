//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UAAdvertiser.h"

@class NSArray, UAUserActivityInfo;

@interface UAActivityReplayAdvertiser : UAAdvertiser
{
    NSArray *_advertisableItems;
    UAUserActivityInfo *_advertisedItem;
}

@property(retain) UAUserActivityInfo *advertisedItem; // @synthesize advertisedItem=_advertisedItem;
- (void).cxx_destruct;
- (void)setItem:(id)arg1;
- (void)setAdvertisableItems:(id)arg1;
- (id)advertisingItems;
- (BOOL)advertising;
- (id)advertisableItems;
- (BOOL)active;

@end

