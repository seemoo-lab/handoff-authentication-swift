//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSFileHandle, NSString, NSURL;

@interface UCExtractor : NSObject
{
    NSURL *_destURL;
    NSString *_uuid;
    NSFileHandle *_archiveReadHandle;
}

@property(retain) NSFileHandle *archiveReadHandle; // @synthesize archiveReadHandle=_archiveReadHandle;
@property(retain) NSString *uuid; // @synthesize uuid=_uuid;
@property(retain) NSURL *destURL; // @synthesize destURL=_destURL;
- (void).cxx_destruct;
- (void)extractArchiveWithCompletion:(CDUnknownBlockType)arg1;
- (id)initWithDestinationURL:(id)arg1 forArchiveUUID:(id)arg2;

@end

