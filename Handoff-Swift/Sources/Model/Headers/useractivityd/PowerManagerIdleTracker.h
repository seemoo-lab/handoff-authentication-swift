//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSDate, NSObject<OS_dispatch_queue>, NSString;

@interface PowerManagerIdleTracker : NSObject
{
    BOOL _active;
    BOOL _enabled;
    BOOL _firstTime;
    double _interval;
    NSString *_name;
    CDUnknownBlockType _block;
    NSObject<OS_dispatch_queue> *_queue;
    unsigned long long _userActivityNotificationRef;
    NSDate *_startTime;
}

+ (unsigned long long)setup:(id)arg1 interval:(double)arg2;
+ (id)idleTracker:(id)arg1 queue:(id)arg2 interval:(double)arg3 block:(CDUnknownBlockType)arg4;
@property BOOL firstTime; // @synthesize firstTime=_firstTime;
@property(retain) NSDate *startTime; // @synthesize startTime=_startTime;
@property unsigned long long userActivityNotificationRef; // @synthesize userActivityNotificationRef=_userActivityNotificationRef;
@property(retain) NSObject<OS_dispatch_queue> *queue; // @synthesize queue=_queue;
@property(copy) CDUnknownBlockType block; // @synthesize block=_block;
@property(readonly) NSString *name; // @synthesize name=_name;
- (void).cxx_destruct;
@property double interval; // @synthesize interval=_interval;
@property BOOL enabled; // @synthesize enabled=_enabled;
@property BOOL active; // @synthesize active=_active;
- (void)invalidate;
- (void)dealloc;
- (id)init:(id)arg1 queue:(id)arg2 interval:(double)arg3 block:(CDUnknownBlockType)arg4;

@end

