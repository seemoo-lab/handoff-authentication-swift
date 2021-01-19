//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSError, NSString;

@interface _LSUserActivityWasContinuedInfo : NSObject
{
    BOOL _submitted;
    BOOL _fromPairedDevice;
    BOOL _browserFallback;
    BOOL _cancelled;
    BOOL _webToNative;
    BOOL _supportsContinuityStreams;
    BOOL _scheduledForSubmission;
    BOOL _payloadRequested;
    int _interactionType;
    NSString *_bundleIdentifier;
    NSString *_activityType;
    unsigned long long _suggestedActionType;
    unsigned long long _payloadSize;
    double _transferSpeed;
    double _transferDuration;
    NSError *_error;
    NSString *_remoteDeviceType;
}

@property BOOL payloadRequested; // @synthesize payloadRequested=_payloadRequested;
@property BOOL scheduledForSubmission; // @synthesize scheduledForSubmission=_scheduledForSubmission;
@property(copy) NSString *remoteDeviceType; // @synthesize remoteDeviceType=_remoteDeviceType;
@property BOOL supportsContinuityStreams; // @synthesize supportsContinuityStreams=_supportsContinuityStreams;
@property BOOL webToNative; // @synthesize webToNative=_webToNative;
@property int interactionType; // @synthesize interactionType=_interactionType;
@property(getter=isCancelled) BOOL cancelled; // @synthesize cancelled=_cancelled;
@property(copy) NSError *error; // @synthesize error=_error;
@property double transferDuration; // @synthesize transferDuration=_transferDuration;
@property double transferSpeed; // @synthesize transferSpeed=_transferSpeed;
@property unsigned long long payloadSize; // @synthesize payloadSize=_payloadSize;
@property(getter=isBrowserFallback) BOOL browserFallback; // @synthesize browserFallback=_browserFallback;
@property(getter=isFromPairedDevice) BOOL fromPairedDevice; // @synthesize fromPairedDevice=_fromPairedDevice;
@property unsigned long long suggestedActionType; // @synthesize suggestedActionType=_suggestedActionType;
@property(copy) NSString *activityType; // @synthesize activityType=_activityType;
@property(copy) NSString *bundleIdentifier; // @synthesize bundleIdentifier=_bundleIdentifier;
- (void).cxx_destruct;
- (id)description;
- (void)submit;
- (void)submitWasSuggestedInfo;

@end
