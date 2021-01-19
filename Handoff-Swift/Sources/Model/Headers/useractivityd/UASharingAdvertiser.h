//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UAAdvertiser.h"

#import "SFActivityAdvertiserDelegate.h"

@class NSArray, NSDate, NSMutableArray, NSMutableDictionary, NSMutableSet, NSObject<OS_dispatch_group>, NSObject<OS_dispatch_queue>, NSSet, NSString, PowerManagerIdleTracker, SharingBTLEAdvertisementPayload, UADispatchScheduler, UATimedPowerAssertions, UAUserActivityInfo;

@interface UASharingAdvertiser : UAAdvertiser <SFActivityAdvertiserDelegate>
{
    NSArray *_advertisableItems;
    NSMutableSet *_sfAdvertisers;
    BOOL _needToRefreshPeerDevices;
    BOOL _shouldAdvertiseHandoff;
    BOOL _shouldAdvertisePasteboard;
    BOOL _userIsCurrent;
    BOOL _pboardBitToAdvertise;
    NSObject<OS_dispatch_group> *_helpersDispatchGroup;
    NSSet *_pairedDevices;
    UAUserActivityInfo *_currentAdvertisedItem;
    NSObject<OS_dispatch_queue> *_dispatchQ;
    UADispatchScheduler *_nextScheduleUpdate;
    UADispatchScheduler *_periodicUpdate;
    NSDate *_dontAdvertiseAsCurrentUntil;
    SharingBTLEAdvertisementPayload *_currentAdvertisementPayload;
    NSDate *_lastAdvertismentTime;
    SharingBTLEAdvertisementPayload *_lastAdvertisementPayload;
    NSMutableDictionary *_currentAdvertisedItemOtherAdvertisedItems;
    NSMutableArray *_advertisementTimes;
    unsigned long long _changeAdvertisementThreadSpinCount;
    UATimedPowerAssertions *_preventIdleSleepAssertion;
    PowerManagerIdleTracker *_userIsCurrentIdleTracker;
    NSDate *_lastUserActiveTime;
    long long _lastAdvertisedGeneration;
}

@property BOOL pboardBitToAdvertise; // @synthesize pboardBitToAdvertise=_pboardBitToAdvertise;
@property long long lastAdvertisedGeneration; // @synthesize lastAdvertisedGeneration=_lastAdvertisedGeneration;
@property(copy) NSDate *lastUserActiveTime; // @synthesize lastUserActiveTime=_lastUserActiveTime;
@property(retain) PowerManagerIdleTracker *userIsCurrentIdleTracker; // @synthesize userIsCurrentIdleTracker=_userIsCurrentIdleTracker;
@property(retain) UATimedPowerAssertions *preventIdleSleepAssertion; // @synthesize preventIdleSleepAssertion=_preventIdleSleepAssertion;
@property unsigned long long changeAdvertisementThreadSpinCount; // @synthesize changeAdvertisementThreadSpinCount=_changeAdvertisementThreadSpinCount;
@property(retain) NSMutableArray *advertisementTimes; // @synthesize advertisementTimes=_advertisementTimes;
@property(retain) NSMutableDictionary *currentAdvertisedItemOtherAdvertisedItems; // @synthesize currentAdvertisedItemOtherAdvertisedItems=_currentAdvertisedItemOtherAdvertisedItems;
@property(copy) SharingBTLEAdvertisementPayload *lastAdvertisementPayload; // @synthesize lastAdvertisementPayload=_lastAdvertisementPayload;
@property(retain) NSDate *lastAdvertismentTime; // @synthesize lastAdvertismentTime=_lastAdvertismentTime;
@property(retain) SharingBTLEAdvertisementPayload *currentAdvertisementPayload; // @synthesize currentAdvertisementPayload=_currentAdvertisementPayload;
@property(retain) NSDate *dontAdvertiseAsCurrentUntil; // @synthesize dontAdvertiseAsCurrentUntil=_dontAdvertiseAsCurrentUntil;
@property(readonly, retain) UADispatchScheduler *periodicUpdate; // @synthesize periodicUpdate=_periodicUpdate;
@property(readonly, retain) UADispatchScheduler *nextScheduleUpdate; // @synthesize nextScheduleUpdate=_nextScheduleUpdate;
@property(readonly, retain) NSObject<OS_dispatch_queue> *dispatchQ; // @synthesize dispatchQ=_dispatchQ;
@property(retain) UAUserActivityInfo *currentAdvertisedItem; // @synthesize currentAdvertisedItem=_currentAdvertisedItem;
@property(readonly, retain) NSObject<OS_dispatch_group> *helpersDispatchGroup; // @synthesize helpersDispatchGroup=_helpersDispatchGroup;
- (void).cxx_destruct;
- (id)statusString;
- (BOOL)pasteboardBitValue;
- (BOOL)pasteboardAvailible;
- (void)removeIOPowerManagerUserIdleNotifications;
- (void)scheduleIOPowerManagerUserIdleNotifications;
@property BOOL userIsCurrent; // @synthesize userIsCurrent=_userIsCurrent;
- (BOOL)resume;
- (BOOL)suspend;
- (BOOL)active;
- (BOOL)okToSuspendAdvertising;
- (BOOL)scheduleAdvertisementUpdate;
- (BOOL)scheduleAdvertisementUpdate:(double)arg1;
- (void)activityAdvertiser:(id)arg1 pairedDevicesChangedNotification:(id)arg2;
- (void)activityAdvertiser:(id)arg1 didSendPayloadForActivityIdentifier:(id)arg2 toDevice:(id)arg3 error:(id)arg4;
- (void)activityAdvertiser:(id)arg1 activityPayloadForAdvertisementPayload:(id)arg2 handoffCommand:(id)arg3 requestedByDevice:(id)arg4 withCompletionHandler:(CDUnknownBlockType)arg5;
- (void)activityAdvertiser:(id)arg1 activityPayloadForAdvertisementPayload:(id)arg2 command:(id)arg3 requestedByDevice:(id)arg4 withCompletionHandler:(CDUnknownBlockType)arg5;
- (void)activityAdvertiser:(id)arg1 activityPayloadForAdvertisementPayload:(id)arg2 requestedByDevice:(id)arg3 withCompletionHandler:(CDUnknownBlockType)arg4;
@property(copy) NSSet *pairedDevices; // @synthesize pairedDevices=_pairedDevices;
- (void)_updatePairedDeviceCapabilities;
- (void)_refreshPairedSFPeerDevices;
@property(readonly) BOOL shouldAdvertisePasteboard; // @synthesize shouldAdvertisePasteboard=_shouldAdvertisePasteboard;
@property(readonly) BOOL shouldAdvertiseHandoff; // @synthesize shouldAdvertiseHandoff=_shouldAdvertiseHandoff;
- (id)sfActivityAdvertiser;
- (BOOL)removeSFActivityAdvertiser:(id)arg1;
- (BOOL)addSFActivityAdvertiser:(id)arg1;
@property(readonly, copy) NSSet *sfActivityAdvertisers;
- (BOOL)peerDeviceCanAcceptNewerPayload:(id)arg1;
- (void)_periodicIdleUpdate;
- (void)removeAdvertisement;
- (BOOL)_updateAdvertisement;
- (BOOL)advertiseItem:(id)arg1 force:(BOOL)arg2;
- (BOOL)_advertisePayload:(id)arg1 force:(BOOL)arg2;
- (BOOL)_advertisePayload:(id)arg1 force:(BOOL)arg2 sfAdvertiser:(id)arg3;
- (BOOL)_advertisePayload:(id)arg1;
- (void)advertisePayload:(id)arg1 force:(BOOL)arg2;
- (void)updateAdvertisingPowerAssertion:(double)arg1;
- (id)mostRecentAdvertisedBytesTime;
- (id)currentAdvertisedBytes;
- (void)setAdvertisableItems:(id)arg1;
- (id)advertisingItems;
- (BOOL)advertising;
- (id)advertisableItems;
- (id)initWithManager:(id)arg1 advertiser:(id)arg2;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end
