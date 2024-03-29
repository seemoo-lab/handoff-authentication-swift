//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

#import "UAStreamHandlerDelegate.h"
#import "UCStreamCoder.h"

@class NSData, NSFileHandle, NSMutableData, NSProgress, NSString, NSTimer, UASharedPasteboardInfoWrapper, UAStreamHandler;

@interface UAPBStreamCoderV1 : NSObject <UAStreamHandlerDelegate, UCStreamCoder>
{
    BOOL _isSendMode;
    BOOL _receivedDelem;
    UAStreamHandler *_streamHandler;
    NSFileHandle *_file;
    NSProgress *_progress;
    CDUnknownBlockType _recvHandler;
    UASharedPasteboardInfoWrapper *_recvRap;
    NSMutableData *_receivedData;
    unsigned long long _streamStartTime;
    unsigned long long _timeRemaining;
    long long _bytesReceived;
    long long _expectedLength;
    unsigned long long _state;
    unsigned long long _totalBytesReceived;
    UASharedPasteboardInfoWrapper *_sendRap;
    NSFileHandle *_dataFile;
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
@property(retain) NSFileHandle *dataFile; // @synthesize dataFile=_dataFile;
@property(retain) UASharedPasteboardInfoWrapper *sendRap; // @synthesize sendRap=_sendRap;
@property unsigned long long totalBytesReceived; // @synthesize totalBytesReceived=_totalBytesReceived;
@property BOOL receivedDelem; // @synthesize receivedDelem=_receivedDelem;
@property unsigned long long state; // @synthesize state=_state;
@property long long expectedLength; // @synthesize expectedLength=_expectedLength;
@property long long bytesReceived; // @synthesize bytesReceived=_bytesReceived;
@property unsigned long long timeRemaining; // @synthesize timeRemaining=_timeRemaining;
@property unsigned long long streamStartTime; // @synthesize streamStartTime=_streamStartTime;
@property(retain) NSMutableData *receivedData; // @synthesize receivedData=_receivedData;
@property(retain) UASharedPasteboardInfoWrapper *recvRap; // @synthesize recvRap=_recvRap;
@property(copy) CDUnknownBlockType recvHandler; // @synthesize recvHandler=_recvHandler;
@property(retain) NSProgress *progress; // @synthesize progress=_progress;
@property(retain) NSFileHandle *file; // @synthesize file=_file;
@property BOOL isSendMode; // @synthesize isSendMode=_isSendMode;
@property(retain) UAStreamHandler *streamHandler; // @synthesize streamHandler=_streamHandler;
- (void).cxx_destruct;
- (id)headerForData:(id)arg1;
- (id)trimFirstBytes:(unsigned long long)arg1 ofData:(id)arg2;
- (void)shutdownTimerFired:(id)arg1;
- (void)receivedDataBack:(id)arg1;
- (void)sendNextChunk;
- (void)sendPasteboard:(id)arg1 withCompletion:(CDUnknownBlockType)arg2;
- (void)processReceivedData;
- (void)streamDoneWithInfo:(id)arg1 error:(id)arg2;
- (void)cancelReceive;
- (void)receivePasteboardToFile:(id)arg1 withProgress:(id)arg2 infoRecievedHandler:(CDUnknownBlockType)arg3 completionHandler:(CDUnknownBlockType)arg4 returnInfoEarly:(BOOL)arg5;
- (void)streamsDidClose:(id)arg1 withError:(id)arg2;
- (void)streams:(id)arg1 didWriteMessageWithTag:(long long)arg2;
- (void)streams:(id)arg1 didReadMessage:(id)arg2 withTag:(long long)arg3;
- (void)streamsDidWriteRawDataBuffer:(id)arg1;
- (void)streams:(id)arg1 didReadRawData:(id)arg2;
- (void)dealloc;
- (id)initWithInputStream:(id)arg1 outputStream:(id)arg2;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

