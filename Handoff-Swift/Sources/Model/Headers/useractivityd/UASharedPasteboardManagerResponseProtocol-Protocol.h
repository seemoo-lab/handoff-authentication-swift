//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSFileHandle;

@protocol UASharedPasteboardManagerResponseProtocol <NSObject>
- (void)tellClientDebuggingEnabled:(BOOL)arg1 logFileHandle:(NSFileHandle *)arg2;
- (void)writeLocalPasteboardToFile:(NSFileHandle *)arg1 withCompletion:(void (^)(UASharedPasteboardInfo *, NSError *))arg2;
@end

