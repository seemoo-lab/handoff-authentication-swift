//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "PBCodable.h"

#import "NSCopying.h"

@class NSString;

@interface AWDHandoffUserActivityWasContinued : PBCodable <NSCopying>
{
    unsigned long long _errorCode;
    unsigned long long _payloadSize;
    unsigned long long _timestamp;
    unsigned long long _transferDurationNsec;
    unsigned long long _transferSpeed;
    NSString *_activityType;
    NSString *_bundleIdentifier;
    NSString *_remoteDeviceType;
    unsigned int _source;
    unsigned int _suggestedActionType;
    BOOL _browserFallback;
    BOOL _cancelled;
    BOOL _supportsContinuityStreams;
    BOOL _webToNative;
    struct {
        unsigned int errorCode:1;
        unsigned int payloadSize:1;
        unsigned int timestamp:1;
        unsigned int transferDurationNsec:1;
        unsigned int transferSpeed:1;
        unsigned int source:1;
        unsigned int suggestedActionType:1;
        unsigned int browserFallback:1;
        unsigned int cancelled:1;
        unsigned int supportsContinuityStreams:1;
        unsigned int webToNative:1;
    } _has;
}

@property(retain, nonatomic) NSString *remoteDeviceType; // @synthesize remoteDeviceType=_remoteDeviceType;
@property(nonatomic) BOOL supportsContinuityStreams; // @synthesize supportsContinuityStreams=_supportsContinuityStreams;
@property(nonatomic) BOOL webToNative; // @synthesize webToNative=_webToNative;
@property(nonatomic) unsigned int suggestedActionType; // @synthesize suggestedActionType=_suggestedActionType;
@property(nonatomic) BOOL browserFallback; // @synthesize browserFallback=_browserFallback;
@property(nonatomic) unsigned int source; // @synthesize source=_source;
@property(nonatomic) BOOL cancelled; // @synthesize cancelled=_cancelled;
@property(nonatomic) unsigned long long errorCode; // @synthesize errorCode=_errorCode;
@property(nonatomic) unsigned long long transferDurationNsec; // @synthesize transferDurationNsec=_transferDurationNsec;
@property(nonatomic) unsigned long long transferSpeed; // @synthesize transferSpeed=_transferSpeed;
@property(nonatomic) unsigned long long payloadSize; // @synthesize payloadSize=_payloadSize;
@property(retain, nonatomic) NSString *activityType; // @synthesize activityType=_activityType;
@property(retain, nonatomic) NSString *bundleIdentifier; // @synthesize bundleIdentifier=_bundleIdentifier;
@property(nonatomic) unsigned long long timestamp; // @synthesize timestamp=_timestamp;
- (void).cxx_destruct;
- (void)mergeFrom:(id)arg1;
- (unsigned long long)hash;
- (BOOL)isEqual:(id)arg1;
- (id)copyWithZone:(struct _NSZone *)arg1;
- (void)copyTo:(id)arg1;
- (void)writeTo:(id)arg1;
- (BOOL)readFrom:(id)arg1;
- (id)dictionaryRepresentation;
- (id)description;
@property(readonly, nonatomic) BOOL hasRemoteDeviceType;
@property(nonatomic) BOOL hasSupportsContinuityStreams;
@property(nonatomic) BOOL hasWebToNative;
@property(nonatomic) BOOL hasSuggestedActionType;
@property(nonatomic) BOOL hasBrowserFallback;
@property(nonatomic) BOOL hasSource;
@property(nonatomic) BOOL hasCancelled;
@property(nonatomic) BOOL hasErrorCode;
@property(nonatomic) BOOL hasTransferDurationNsec;
@property(nonatomic) BOOL hasTransferSpeed;
@property(nonatomic) BOOL hasPayloadSize;
@property(readonly, nonatomic) BOOL hasActivityType;
@property(readonly, nonatomic) BOOL hasBundleIdentifier;
@property(nonatomic) BOOL hasTimestamp;

@end

