//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UACornerActionManagerHandler.h"

#import "UAActivityNotifierProtocol.h"

@class NSSet;

@interface UAActivityNotifier : UACornerActionManagerHandler <UAActivityNotifierProtocol>
{
}

- (id)initWithManager:(id)arg1 name:(id)arg2;
@property(copy) NSSet *items; // @dynamic items;
@property(copy) NSSet *notifiedItems; // @dynamic notifiedItems;

@end

