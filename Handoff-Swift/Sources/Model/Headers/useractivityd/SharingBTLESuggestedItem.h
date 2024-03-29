//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UAUserActivityInfo.h"

@class NSData, NSDate, NSMutableSet, NSSet, SFActivityScanner, SharingBTLEAdvertisementPayload, UACornerActionManager, UASharingReceiver;

@interface SharingBTLESuggestedItem : UAUserActivityInfo
{
    unsigned int _optionBits;
    NSDate *_currentUntilDate;
    SFActivityScanner *_scanner;
    SharingBTLEAdvertisementPayload *_advertisementPayload;
    double _payloadAvailabilityDelay;
    NSMutableSet *_payloadRequestedCompletions;
    UASharingReceiver *_receiver;
    UACornerActionManager *_manager;
    NSSet *_teamIDs;
    NSDate *_dontPrefetchBefore;
    NSDate *_removeAfter;
}

+ (id)statusString;
+ (id)cornerActionBTLEItemWithSFAdvertisement:(id)arg1 optionBits:(unsigned int)arg2 scanner:(id)arg3 receiver:(id)arg4;
@property(copy) NSDate *removeAfter; // @synthesize removeAfter=_removeAfter;
@property(copy) NSDate *dontPrefetchBefore; // @synthesize dontPrefetchBefore=_dontPrefetchBefore;
@property(copy) NSSet *teamIDs; // @synthesize teamIDs=_teamIDs;
@property unsigned int optionBits; // @synthesize optionBits=_optionBits;
@property(readonly, retain) UACornerActionManager *manager; // @synthesize manager=_manager;
@property(readonly, retain) UASharingReceiver *receiver; // @synthesize receiver=_receiver;
@property(retain) NSMutableSet *payloadRequestedCompletions; // @synthesize payloadRequestedCompletions=_payloadRequestedCompletions;
@property double payloadAvailabilityDelay; // @synthesize payloadAvailabilityDelay=_payloadAvailabilityDelay;
@property(copy) SharingBTLEAdvertisementPayload *advertisementPayload; // @synthesize advertisementPayload=_advertisementPayload;
@property(readonly, retain) SFActivityScanner *scanner; // @synthesize scanner=_scanner;
@property(copy) NSDate *currentUntilDate; // @synthesize currentUntilDate=_currentUntilDate;
- (void).cxx_destruct;
- (id)description;
- (void)setWhen:(id)arg1;
- (id)when;
- (id)statusString;
- (void)clearPayload;
- (BOOL)requestPayloadWithCompletionHandler:(CDUnknownBlockType)arg1;
- (BOOL)updateFromSFAdvertisement:(id)arg1;
- (id)initWithSFAdvertisement:(id)arg1 optionBits:(unsigned int)arg2 type:(unsigned long long)arg3 activityType:(id)arg4 bundleIdentifier:(id)arg5 teamIDs:(id)arg6 advertisingOptions:(id)arg7 scanner:(id)arg8 receiver:(id)arg9;
- (id)initWithSFAdvertisement:(id)arg1 optionBits:(unsigned int)arg2 type:(unsigned long long)arg3 activityType:(id)arg4 bundleIdentifier:(id)arg5 teamIDs:(id)arg6 advertisingOptions:(id)arg7 scanner:(id)arg8 receiver:(id)arg9 dynamicIdentifier:(id)arg10;

// Remaining properties
@property(readonly, copy) NSData *BTLEPayloadData; // @dynamic BTLEPayloadData;

@end

