//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UACornerActionManagerHandler.h"

@class NSSet;

@interface UAReceiver : UACornerActionManagerHandler
{
    NSSet *scanningForTypes;
}

@property(copy) NSSet *scanningForTypes; // @synthesize scanningForTypes;
- (void).cxx_destruct;
- (id)statusString;
- (BOOL)terminate;
- (id)receivedItems;
@property(readonly) BOOL receiving; // @dynamic receiving;
- (id)initWithManager:(id)arg1 name:(id)arg2;

@end

