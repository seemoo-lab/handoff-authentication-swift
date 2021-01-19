//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UAClientController.h"

#import "NSXPCListenerDelegate.h"
#import "SFCompanionAdvertiserDelegate.h"
#import "UASharedPasteboardAUXProtocol.h"
#import "UASharedPasteboardControllProtocol.h"
#import "UASharedPasteboardManagerProtocol.h"

@class AWDHandoffDidSendLocalPasteboard, AWDHandoffRemotePasteboardWasRequested, NSArray, NSBundle, NSDate, NSMutableSet, NSMutableSet<UCStreamCoder>, NSObject<OS_dispatch_queue>, NSObject<OS_dispatch_semaphore>, NSProgress, NSString, NSTimer, NSXPCConnection, NSXPCListener, SFCompanionAdvertiser, UASharedPasteboardInfo, UASharedPasteboardInfoWrapper, UASharedPasteboardInputStreamManager, UASharedPasteboardOutputStreamManager, UCRemotePasteboardGeneration;

@interface UASharedPasteboardClientController : UAClientController <UASharedPasteboardManagerProtocol, SFCompanionAdvertiserDelegate, UASharedPasteboardAUXProtocol, UASharedPasteboardControllProtocol, NSXPCListenerDelegate>
{
    BOOL _screenWatcherPresent;
    BOOL _hasFetchedLocalData;
    BOOL _advertiseTypes;
    BOOL _remoteAvalible;
    BOOL _isUIVisible;
    NSObject<OS_dispatch_queue> *_clientq;
    NSXPCListener *_xpclistener;
    NSXPCListener *_auxlistener;
    NSXPCListener *_controllListener;
    NSXPCConnection *_auxConnection;
    NSXPCConnection *_clientConnection;
    NSXPCConnection *_clientNotificationConnection;
    NSMutableSet *_controllConnections;
    UASharedPasteboardInfo *_currentLocalTypes;
    unsigned long long _currentLocalGeneration;
    NSTimer *_localTimeout;
    NSArray *_currentLocalPasteboard;
    long long _currentLocalPasteboardSize;
    SFCompanionAdvertiser *_pasteAdvertiser;
    UCRemotePasteboardGeneration *_remoteGeneration;
    NSObject<OS_dispatch_semaphore> *_pboardFetchSem;
    UASharedPasteboardInfoWrapper *_pboardInfoToSend;
    UASharedPasteboardOutputStreamManager *_outStream;
    UASharedPasteboardInputStreamManager *_inStream;
    NSMutableSet<UCStreamCoder> *_coders;
    long long _sendingCoderVersion;
    NSProgress *_fetchProgress;
    NSTimer *_showUITimer;
    NSDate *_dontHideUIBefore;
    NSXPCConnection *_osxUIConnection;
    struct __CFUserNotification *_notificationRef;
    unsigned long long _pasteFetchStartTime;
    unsigned long long _localSendStartTime;
    unsigned long long _streamOpenStartTime;
    unsigned long long _streamXferStartTime;
    AWDHandoffRemotePasteboardWasRequested *_pasteInfo;
    AWDHandoffDidSendLocalPasteboard *_localInfo;
    NSBundle *_uaBundle;
}

@property(retain) NSBundle *uaBundle; // @synthesize uaBundle=_uaBundle;
@property(retain) AWDHandoffDidSendLocalPasteboard *localInfo; // @synthesize localInfo=_localInfo;
@property(retain) AWDHandoffRemotePasteboardWasRequested *pasteInfo; // @synthesize pasteInfo=_pasteInfo;
@property unsigned long long streamXferStartTime; // @synthesize streamXferStartTime=_streamXferStartTime;
@property unsigned long long streamOpenStartTime; // @synthesize streamOpenStartTime=_streamOpenStartTime;
@property unsigned long long localSendStartTime; // @synthesize localSendStartTime=_localSendStartTime;
@property unsigned long long pasteFetchStartTime; // @synthesize pasteFetchStartTime=_pasteFetchStartTime;
@property struct __CFUserNotification *notificationRef; // @synthesize notificationRef=_notificationRef;
@property(retain) NSXPCConnection *osxUIConnection; // @synthesize osxUIConnection=_osxUIConnection;
@property BOOL isUIVisible; // @synthesize isUIVisible=_isUIVisible;
@property(retain) NSDate *dontHideUIBefore; // @synthesize dontHideUIBefore=_dontHideUIBefore;
@property(retain) NSTimer *showUITimer; // @synthesize showUITimer=_showUITimer;
@property(retain) NSProgress *fetchProgress; // @synthesize fetchProgress=_fetchProgress;
@property long long sendingCoderVersion; // @synthesize sendingCoderVersion=_sendingCoderVersion;
@property(retain) NSMutableSet<UCStreamCoder> *coders; // @synthesize coders=_coders;
@property(retain) UASharedPasteboardInputStreamManager *inStream; // @synthesize inStream=_inStream;
@property(retain) UASharedPasteboardOutputStreamManager *outStream; // @synthesize outStream=_outStream;
@property(retain) UASharedPasteboardInfoWrapper *pboardInfoToSend; // @synthesize pboardInfoToSend=_pboardInfoToSend;
@property(retain) NSObject<OS_dispatch_semaphore> *pboardFetchSem; // @synthesize pboardFetchSem=_pboardFetchSem;
@property(retain) UCRemotePasteboardGeneration *remoteGeneration; // @synthesize remoteGeneration=_remoteGeneration;
@property(retain) SFCompanionAdvertiser *pasteAdvertiser; // @synthesize pasteAdvertiser=_pasteAdvertiser;
@property BOOL remoteAvalible; // @synthesize remoteAvalible=_remoteAvalible;
@property BOOL advertiseTypes; // @synthesize advertiseTypes=_advertiseTypes;
@property long long currentLocalPasteboardSize; // @synthesize currentLocalPasteboardSize=_currentLocalPasteboardSize;
@property(retain) NSArray *currentLocalPasteboard; // @synthesize currentLocalPasteboard=_currentLocalPasteboard;
@property BOOL hasFetchedLocalData; // @synthesize hasFetchedLocalData=_hasFetchedLocalData;
@property(retain) NSTimer *localTimeout; // @synthesize localTimeout=_localTimeout;
@property unsigned long long currentLocalGeneration; // @synthesize currentLocalGeneration=_currentLocalGeneration;
@property(retain) UASharedPasteboardInfo *currentLocalTypes; // @synthesize currentLocalTypes=_currentLocalTypes;
@property(retain) NSMutableSet *controllConnections; // @synthesize controllConnections=_controllConnections;
@property(retain) NSXPCConnection *clientNotificationConnection; // @synthesize clientNotificationConnection=_clientNotificationConnection;
@property(retain) NSXPCConnection *clientConnection; // @synthesize clientConnection=_clientConnection;
@property(retain) NSXPCConnection *auxConnection; // @synthesize auxConnection=_auxConnection;
@property(retain) NSXPCListener *controllListener; // @synthesize controllListener=_controllListener;
@property(retain) NSXPCListener *auxlistener; // @synthesize auxlistener=_auxlistener;
@property(retain) NSXPCListener *xpclistener; // @synthesize xpclistener=_xpclistener;
@property(retain) NSObject<OS_dispatch_queue> *clientq; // @synthesize clientq=_clientq;
- (void).cxx_destruct;
- (id)localPBStatus;
- (id)statusString;
- (void)hideProgressUI:(BOOL)arg1;
- (void)showProgressUI:(id)arg1;
- (BOOL)listener:(id)arg1 shouldAcceptNewConnection:(id)arg2;
- (void)advertiser:(id)arg1 didReceiveInputStream:(id)arg2 outputStream:(id)arg3;
- (void)startServiceForPasteVersion:(long long)arg1 handler:(CDUnknownBlockType)arg2;
- (void)getLocalPasteboardInfoData:(CDUnknownBlockType)arg1;
- (void)setLocalPasteboardReflection:(BOOL)arg1;
- (void)receivePasteboardStreamData:(id)arg1 version:(long long)arg2 withCompletion:(CDUnknownBlockType)arg3;
- (void)fetchRemotePasteboardForProcess:(int)arg1 withCompletion:(CDUnknownBlockType)arg2;
- (void)fetchRemotePasteboardTypesForProcess:(int)arg1 withCompletion:(CDUnknownBlockType)arg2;
- (void)removeLocalPasteboardFromAdvertisers:(id)arg1;
- (void)clearLocalPasteboardTypes:(id)arg1;
- (void)clearLocalPasteboardInformation;
- (void)localPasteboardTypesDidChange:(id)arg1 forGeneration:(unsigned long long)arg2;
- (void)fetchRemotePasteboardStatus:(CDUnknownBlockType)arg1;
- (void)setReturnPasteboardDataEarlyWithCompletion:(CDUnknownBlockType)arg1;
- (void)setRemotePasteboardAvalibility:(BOOL)arg1 withDataRequester:(id)arg2;
- (id)currentPasteboardActivityInfo;
- (id)eligibleAdvertiseableItemsInOrder;
- (id)items;
- (void)startConnection:(int)arg1;
@property(getter=isScreenWatcherPresent) BOOL screenWatcherPresent; // @synthesize screenWatcherPresent=_screenWatcherPresent;
@property BOOL localReflection;
- (id)uuid;
- (void)dealloc;
- (id)initWithManager:(id)arg1 name:(id)arg2;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

