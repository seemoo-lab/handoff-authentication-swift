//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

#import "NSStreamDelegate.h"

@class NSData, NSFileHandle, NSInputStream, NSOutputStream, NSSet, NSString, NSTimer, UASharedPasteboardInfoWrapper;

@interface UASharedPasteboardOutputStreamManager : NSObject <NSStreamDelegate>
{
    NSOutputStream *_stream;
    NSInputStream *_inStream;
    UASharedPasteboardInfoWrapper *_pbwrapper;
    NSFileHandle *_dataFile;
    NSSet *_typesToSend;
    CDUnknownBlockType _sendErrorHandler;
    NSData *_currentSendData;
    long long _byteIndex;
    char *_infoSent;
    unsigned long long _dataSent;
    NSTimer *_backupTimer;
}

@property(retain) NSTimer *backupTimer; // @synthesize backupTimer=_backupTimer;
@property unsigned long long dataSent; // @synthesize dataSent=_dataSent;
@property char *infoSent; // @synthesize infoSent=_infoSent;
@property long long byteIndex; // @synthesize byteIndex=_byteIndex;
@property(retain) NSData *currentSendData; // @synthesize currentSendData=_currentSendData;
@property(copy) CDUnknownBlockType sendErrorHandler; // @synthesize sendErrorHandler=_sendErrorHandler;
@property(retain) NSSet *typesToSend; // @synthesize typesToSend=_typesToSend;
@property(retain) NSFileHandle *dataFile; // @synthesize dataFile=_dataFile;
@property(retain) UASharedPasteboardInfoWrapper *pbwrapper; // @synthesize pbwrapper=_pbwrapper;
@property(retain) NSInputStream *inStream; // @synthesize inStream=_inStream;
@property(retain) NSOutputStream *stream; // @synthesize stream=_stream;
- (void).cxx_destruct;
- (void)shutdownStream;
- (void)shutdownTimerFired:(id)arg1;
- (void)stream:(id)arg1 handleEvent:(unsigned long long)arg2;
- (id)headerForData:(id)arg1;
- (void)sendTypes:(id)arg1 completionHandler:(CDUnknownBlockType)arg2;
- (id)initWithOutputStream:(id)arg1 inputStream:(id)arg2 pasteboard:(id)arg3;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end
