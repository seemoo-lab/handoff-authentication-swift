//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UAAdvertisableItem.h"

@class NSObject<OS_dispatch_semaphore>;

@interface UAReplayAdvertisableItem : UAAdvertisableItem
{
    NSObject<OS_dispatch_semaphore> *_wasResumed;
}

+ (id)replayableAdvertisableItemWithAdvertisableItem:(id)arg1;
@property(readonly, retain) NSObject<OS_dispatch_semaphore> *wasResumed; // @synthesize wasResumed=_wasResumed;
- (void).cxx_destruct;
- (BOOL)wasResumedOnAnotherDeviceWithCompletionHandler:(CDUnknownBlockType)arg1;
- (void)encodeWithCoder:(id)arg1;
- (id)initWithCoder:(id)arg1;
- (id)initWithUUID:(id)arg1;

@end

