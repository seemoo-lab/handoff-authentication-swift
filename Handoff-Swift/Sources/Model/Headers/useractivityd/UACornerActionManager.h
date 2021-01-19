//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

#import "NSXPCListenerDelegate.h"
#import "UACornerActionManagerDebugInterface.h"

@class ActivityManagerDebuggingManager, NSArray, NSDate, NSMutableSet, NSObject<OS_dispatch_group>, NSObject<OS_dispatch_queue>, NSObject<OS_dispatch_semaphore>, NSObject<OS_dispatch_source>, NSSet, NSString, NSTimer, NSUUID, NSUserDefaults, PowerManagerIdleTracker, UADispatchScheduler, UAPingController, UAPingResults, UASharedPasteboardClientController, UATimedPowerAssertions, UAUserActivityInfo;

@interface UACornerActionManager : NSObject <NSXPCListenerDelegate, UACornerActionManagerDebugInterface>
{
    BOOL _suspended;
    NSMutableSet *_advertisers;
    NSMutableSet *_receivers;
    NSMutableSet *_clients;
    NSMutableSet *_notifiers;
    NSMutableSet *_handlers;
    NSDate *_creationTime;
    NSArray *_itemsBeingAdvertised;
    int _managedSettingsChangedNotificationToken;
    NSObject<OS_dispatch_group> *_helpersDispatchGroup;
    double _systemIdlePreviousTimeSinceLastUserActivity;
    BOOL _advertisingSuspended;
    BOOL _backlightOn;
    BOOL _screenSaverActive;
    BOOL _systemHasSuspendedAdvertisements;
    BOOL _systemHasSuspendedScanning;
    BOOL _userActive;
    BOOL _batterySaverModeEnabled;
    BOOL _receivingSuspended;
    BOOL _deviceUILocked;
    BOOL _screenDimmed;
    BOOL _systemIsIdle;
    BOOL _onConsole;
    BOOL _pingMode;
    int _backlightLevelToken;
    unsigned int _holdPowerAssertion;
    int _consoleUserChangedToken;
    int _systemPreferenceChangedToken;
    UATimedPowerAssertions *_screenSaverActivePowerAssertion;
    NSUUID *_uuid;
    NSSet *_activeDevicesIdentifiers;
    NSUserDefaults *_userDefaults;
    ActivityManagerDebuggingManager *_debugManager;
    UAUserActivityInfo *_pinnedUserActivityInfoItem;
    UASharedPasteboardClientController *_pasteboardController;
    UAPingController *_pingController;
    NSObject<OS_dispatch_queue> *_mainDispatchQ;
    UADispatchScheduler *_nextUserIdleDeterminationScheduler;
    UADispatchScheduler *_nextUpdateAdvertisedItemsScheduler;
    UADispatchScheduler *_nextScheduleBestAppDeterminationScheduler;
    UATimedPowerAssertions *_deviceUILockedPowerAssertion;
    UATimedPowerAssertions *_screenDimmedPowerAssertion;
    NSDate *_holdPowerAssertionUntil;
    NSObject<OS_dispatch_source> *_holdPowerAssertionSourceTimer;
    PowerManagerIdleTracker *_userIdleTracker;
    UATimedPowerAssertions *_userInactivePowerAssertion;
    NSDate *_lastTimePayloadWasRequestedForAdvertisedItem;
    double _avgPingTime;
    NSDate *_pingStart;
    NSObject<OS_dispatch_semaphore> *_pongSem;
    UAPingResults *_pongs;
    NSTimer *_pongTimer;
}

+ (id)sharedActivityManagerServer;
+ (id)cornerActionManager;
@property(retain) NSTimer *pongTimer; // @synthesize pongTimer=_pongTimer;
@property(retain) UAPingResults *pongs; // @synthesize pongs=_pongs;
@property(retain) NSObject<OS_dispatch_semaphore> *pongSem; // @synthesize pongSem=_pongSem;
@property(retain) NSDate *pingStart; // @synthesize pingStart=_pingStart;
@property double avgPingTime; // @synthesize avgPingTime=_avgPingTime;
@property BOOL pingMode; // @synthesize pingMode=_pingMode;
@property int systemPreferenceChangedToken; // @synthesize systemPreferenceChangedToken=_systemPreferenceChangedToken;
@property BOOL onConsole; // @synthesize onConsole=_onConsole;
@property int consoleUserChangedToken; // @synthesize consoleUserChangedToken=_consoleUserChangedToken;
@property(copy) NSDate *lastTimePayloadWasRequestedForAdvertisedItem; // @synthesize lastTimePayloadWasRequestedForAdvertisedItem=_lastTimePayloadWasRequestedForAdvertisedItem;
@property BOOL systemIsIdle; // @synthesize systemIsIdle=_systemIsIdle;
@property(retain) UATimedPowerAssertions *userInactivePowerAssertion; // @synthesize userInactivePowerAssertion=_userInactivePowerAssertion;
@property(retain) PowerManagerIdleTracker *userIdleTracker; // @synthesize userIdleTracker=_userIdleTracker;
@property unsigned int holdPowerAssertion; // @synthesize holdPowerAssertion=_holdPowerAssertion;
@property(retain) NSObject<OS_dispatch_source> *holdPowerAssertionSourceTimer; // @synthesize holdPowerAssertionSourceTimer=_holdPowerAssertionSourceTimer;
@property(retain) NSDate *holdPowerAssertionUntil; // @synthesize holdPowerAssertionUntil=_holdPowerAssertionUntil;
@property int backlightLevelToken; // @synthesize backlightLevelToken=_backlightLevelToken;
@property(retain) UATimedPowerAssertions *screenDimmedPowerAssertion; // @synthesize screenDimmedPowerAssertion=_screenDimmedPowerAssertion;
@property BOOL screenDimmed; // @synthesize screenDimmed=_screenDimmed;
@property(retain) UATimedPowerAssertions *deviceUILockedPowerAssertion; // @synthesize deviceUILockedPowerAssertion=_deviceUILockedPowerAssertion;
@property BOOL deviceUILocked; // @synthesize deviceUILocked=_deviceUILocked;
@property(readonly, retain) UADispatchScheduler *nextScheduleBestAppDeterminationScheduler; // @synthesize nextScheduleBestAppDeterminationScheduler=_nextScheduleBestAppDeterminationScheduler;
@property(readonly, retain) UADispatchScheduler *nextUpdateAdvertisedItemsScheduler; // @synthesize nextUpdateAdvertisedItemsScheduler=_nextUpdateAdvertisedItemsScheduler;
@property(readonly, retain) UADispatchScheduler *nextUserIdleDeterminationScheduler; // @synthesize nextUserIdleDeterminationScheduler=_nextUserIdleDeterminationScheduler;
@property(retain) NSObject<OS_dispatch_queue> *mainDispatchQ; // @synthesize mainDispatchQ=_mainDispatchQ;
@property(retain) UAPingController *pingController; // @synthesize pingController=_pingController;
@property(retain) UASharedPasteboardClientController *pasteboardController; // @synthesize pasteboardController=_pasteboardController;
@property BOOL receivingSuspended; // @synthesize receivingSuspended=_receivingSuspended;
@property(retain) UAUserActivityInfo *pinnedUserActivityInfoItem; // @synthesize pinnedUserActivityInfoItem=_pinnedUserActivityInfoItem;
@property(readonly, retain) ActivityManagerDebuggingManager *debugManager; // @synthesize debugManager=_debugManager;
@property(readonly, getter=isBatterySaverModeEnabled) BOOL batterySaverModeEnabled; // @synthesize batterySaverModeEnabled=_batterySaverModeEnabled;
@property(readonly, retain) NSUserDefaults *userDefaults; // @synthesize userDefaults=_userDefaults;
@property(readonly) NSSet *activeDevicesIdentifiers; // @synthesize activeDevicesIdentifiers=_activeDevicesIdentifiers;
@property(readonly, copy) NSUUID *uuid; // @synthesize uuid=_uuid;
@property(getter=isBacklightOn) BOOL backlightOn; // @synthesize backlightOn=_backlightOn;
- (void).cxx_destruct;
@property(readonly, copy) NSSet *allHandlers;
- (void)removeHandler:(id)arg1;
- (void)addHandler:(id)arg1;
@property(readonly, copy) NSSet *handlers;
- (void)removeActivityNotifier:(id)arg1;
- (void)addActivityNotifier:(id)arg1;
@property(readonly, copy) NSSet *notifiers;
- (void)removeClient:(id)arg1;
- (void)addClient:(id)arg1;
@property(readonly, copy) NSSet *clients;
- (void)removeReceiver:(id)arg1;
- (void)addReceiver:(id)arg1;
@property(readonly, copy) NSSet *receivers;
- (void)removeAdvertiser:(id)arg1;
- (void)addAdvertiser:(id)arg1;
@property(readonly, copy) NSSet *advertisers;
- (id)statusString;
- (id)shortStatusString;
- (id)dynamicUserActivitiesString;
- (id)debuggingInfo;
- (id)dictionaryForCornerActionItem:(id)arg1;
- (id)dictionaryForAdvertisableItem:(id)arg1;
- (void)updateUIDeviceLockedState:(BOOL)arg1;
- (void)updateScreenDimStateState:(BOOL)arg1;
- (void)updateUserActiveState:(BOOL)arg1;
@property BOOL userActive; // @synthesize userActive=_userActive;
- (void)terminate;
- (void)resume;
- (void)suspend;
@property BOOL suspended;
- (void)resumeListeningForBluetooth;
- (void)suspendListeningForBluetooth;
- (void)bluetoothAvailabilityChange:(id)arg1;
- (void)bluetoothPowerChanged:(id)arg1;
- (void)triggerAll;
- (BOOL)haveBestAppChangeNotificationClients;
- (void)_checkIfBestApplicationChangedThread;
- (BOOL)scheduleBestAppDetermination:(double)arg1;
- (BOOL)scheduleBestAppDetermination;
- (void)checkIfBestCornerItemChanged:(double)arg1;
- (id)bestCornerItem:(id)arg1;
- (id)bestCornerItem;
- (id)cornerActionItemForUUID:(id)arg1;
- (id)cornerActionItems;
@property BOOL systemHasSuspendedScanning; // @synthesize systemHasSuspendedScanning=_systemHasSuspendedScanning;
@property BOOL systemHasSuspendedAdvertisements; // @synthesize systemHasSuspendedAdvertisements=_systemHasSuspendedAdvertisements;
- (void)_determineWhenSystemGoesIdleThread;
@property BOOL advertisingSuspended;
- (void)triggerUserIdleDetermination:(double)arg1;
- (void)triggerUserIdleDetermination;
- (BOOL)isBluetoothEnabled;
@property(readonly) BOOL activityReceivingAllowed;
@property(readonly) BOOL activityAdvertisingAllowed;
- (void)distributedNotificationHook:(id)arg1;
- (void)updateScreenSaverActive:(BOOL)arg1;
@property(retain) UATimedPowerAssertions *screenSaverActivePowerAssertion; // @synthesize screenSaverActivePowerAssertion=_screenSaverActivePowerAssertion;
@property BOOL screenSaverActive; // @synthesize screenSaverActive=_screenSaverActive;
- (void)_determineItemToAdvertiseForHandoffThread;
@property(readonly, copy) NSArray *itemsBeingAdvertised; // @synthesize itemsBeingAdvertised=_itemsBeingAdvertised;
- (BOOL)weAreAdvertisingAtLeastOneItem;
- (void)userActivityItemsChanged;
- (id)uaAdvertisableItemsInOrder:(BOOL)arg1;
- (id)uaAdvertisableItemsInOrder;
- (id)activeAdvertiseableItemsUUIDs;
- (void)scheduleUpdatingAdvertisableItems:(double)arg1;
- (void)scheduleUpdatingAdvertisableItems;
- (id)advertiseableItems;
- (BOOL)weAreAdvertisingAnItem;
- (void)dealloc;
- (id)init;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

