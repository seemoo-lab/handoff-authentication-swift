//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UAUserActivityInfo.h"

@interface UAAdvertisableItem : UAUserActivityInfo
{
    BOOL _alwaysPick;
    BOOL _alwaysEligible;
    long long _alwaysPickValue;
}

@property(readonly) BOOL alwaysEligible; // @synthesize alwaysEligible=_alwaysEligible;
@property(readonly) long long alwaysPickValue; // @synthesize alwaysPickValue=_alwaysPickValue;
@property(readonly) BOOL alwaysPick; // @synthesize alwaysPick=_alwaysPick;
- (id)statusString;
- (id)logString;
- (id)description;

@end

