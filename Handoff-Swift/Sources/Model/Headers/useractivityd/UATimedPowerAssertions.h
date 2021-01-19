//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSDate, NSObject<OS_dispatch_queue>, NSObject<OS_dispatch_source>, NSString, NSUUID;

@interface UATimedPowerAssertions : NSObject
{
    BOOL _needToCallBlock;
    unsigned int _assertion;
    NSString *_name;
    NSObject<OS_dispatch_queue> *_mainDispatchQ;
    CDUnknownBlockType _block;
    NSUUID *_uuid;
    NSObject<OS_dispatch_source> *_timerSource;
    NSDate *_timerExpiration;
    unsigned long long _nextTimer;
}

+ (id)statusString;
@property unsigned long long nextTimer; // @synthesize nextTimer=_nextTimer;
@property(copy) NSDate *timerExpiration; // @synthesize timerExpiration=_timerExpiration;
@property(readonly, retain) NSObject<OS_dispatch_source> *timerSource; // @synthesize timerSource=_timerSource;
@property(readonly, copy) NSUUID *uuid; // @synthesize uuid=_uuid;
@property(copy) CDUnknownBlockType block; // @synthesize block=_block;
@property BOOL needToCallBlock; // @synthesize needToCallBlock=_needToCallBlock;
@property(readonly, retain) NSObject<OS_dispatch_queue> *mainDispatchQ; // @synthesize mainDispatchQ=_mainDispatchQ;
@property(readonly) unsigned int assertion; // @synthesize assertion=_assertion;
@property(readonly, copy) NSString *name; // @synthesize name=_name;
- (void).cxx_destruct;
- (void)releaseAssertion;
- (void)releaseAssertion:(BOOL)arg1;
- (void)_releaseAssertion:(BOOL)arg1;
- (void)updateTimeUntilAssertionRelease:(double)arg1;
@property(readonly) BOOL active;
- (void)dealloc;
- (id)initWithName:(id)arg1 delta:(double)arg2 queue:(id)arg3;
- (id)initWithName:(id)arg1 delta:(double)arg2 queue:(id)arg3 runAtCompletion:(CDUnknownBlockType)arg4;

@end

