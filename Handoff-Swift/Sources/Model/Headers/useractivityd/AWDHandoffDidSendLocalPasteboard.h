//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "PBCodable.h"

#import "NSCopying.h"

@interface AWDHandoffDidSendLocalPasteboard : PBCodable <NSCopying>
{
    unsigned long long _clientWriteSize;
    unsigned long long _clientWriteSpeed;
    unsigned long long _clientWriteTime;
    long long _errorCode;
    unsigned long long _streamDataSize;
    unsigned long long _streamDataXferSpeed;
    unsigned long long _streamDataXferTime;
    unsigned long long _streamOpenDelay;
    unsigned long long _timestamp;
    unsigned long long _totalTime;
    BOOL _usedStreams;
    struct {
        unsigned int clientWriteSize:1;
        unsigned int clientWriteSpeed:1;
        unsigned int clientWriteTime:1;
        unsigned int errorCode:1;
        unsigned int streamDataSize:1;
        unsigned int streamDataXferSpeed:1;
        unsigned int streamDataXferTime:1;
        unsigned int streamOpenDelay:1;
        unsigned int timestamp:1;
        unsigned int totalTime:1;
        unsigned int usedStreams:1;
    } _has;
}

@property(nonatomic) long long errorCode; // @synthesize errorCode=_errorCode;
@property(nonatomic) unsigned long long totalTime; // @synthesize totalTime=_totalTime;
@property(nonatomic) unsigned long long streamDataXferSpeed; // @synthesize streamDataXferSpeed=_streamDataXferSpeed;
@property(nonatomic) unsigned long long streamDataXferTime; // @synthesize streamDataXferTime=_streamDataXferTime;
@property(nonatomic) unsigned long long streamDataSize; // @synthesize streamDataSize=_streamDataSize;
@property(nonatomic) unsigned long long streamOpenDelay; // @synthesize streamOpenDelay=_streamOpenDelay;
@property(nonatomic) BOOL usedStreams; // @synthesize usedStreams=_usedStreams;
@property(nonatomic) unsigned long long clientWriteSpeed; // @synthesize clientWriteSpeed=_clientWriteSpeed;
@property(nonatomic) unsigned long long clientWriteTime; // @synthesize clientWriteTime=_clientWriteTime;
@property(nonatomic) unsigned long long clientWriteSize; // @synthesize clientWriteSize=_clientWriteSize;
@property(nonatomic) unsigned long long timestamp; // @synthesize timestamp=_timestamp;
- (void)mergeFrom:(id)arg1;
- (unsigned long long)hash;
- (BOOL)isEqual:(id)arg1;
- (id)copyWithZone:(struct _NSZone *)arg1;
- (void)copyTo:(id)arg1;
- (void)writeTo:(id)arg1;
- (BOOL)readFrom:(id)arg1;
- (id)dictionaryRepresentation;
- (id)description;
@property(nonatomic) BOOL hasErrorCode;
@property(nonatomic) BOOL hasTotalTime;
@property(nonatomic) BOOL hasStreamDataXferSpeed;
@property(nonatomic) BOOL hasStreamDataXferTime;
@property(nonatomic) BOOL hasStreamDataSize;
@property(nonatomic) BOOL hasStreamOpenDelay;
@property(nonatomic) BOOL hasUsedStreams;
@property(nonatomic) BOOL hasClientWriteSpeed;
@property(nonatomic) BOOL hasClientWriteTime;
@property(nonatomic) BOOL hasClientWriteSize;
@property(nonatomic) BOOL hasTimestamp;

@end

