//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSFileHandle, NSProgress, UASharedPasteboardInfoWrapper;

@protocol UCStreamCoder <NSObject>
- (void)sendPasteboard:(UASharedPasteboardInfoWrapper *)arg1 withCompletion:(void (^)(id <UCStreamCoder>, unsigned long long, NSError *))arg2;
- (void)cancelReceive;
- (void)receivePasteboardToFile:(NSFileHandle *)arg1 withProgress:(NSProgress *)arg2 infoRecievedHandler:(void (^)(UASharedPasteboardInfoWrapper *, NSError *))arg3 completionHandler:(void (^)(id <UCStreamCoder>, unsigned long long, NSError *))arg4 returnInfoEarly:(BOOL)arg5;
@end

