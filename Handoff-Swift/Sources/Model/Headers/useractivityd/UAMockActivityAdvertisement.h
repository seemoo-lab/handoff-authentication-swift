//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

#import "NSSecureCoding.h"

@class NSData, NSDictionary, SFPeerDevice;

@interface UAMockActivityAdvertisement : NSObject <NSSecureCoding>
{
    long long _advertisementVersion;
    NSData *_advertisementPayload;
    NSDictionary *_options;
    SFPeerDevice *_device;
}

+ (BOOL)supportsSecureCoding;
@property(retain) SFPeerDevice *device; // @synthesize device=_device;
@property(copy) NSDictionary *options; // @synthesize options=_options;
@property(copy) NSData *advertisementPayload; // @synthesize advertisementPayload=_advertisementPayload;
@property long long advertisementVersion; // @synthesize advertisementVersion=_advertisementVersion;
- (void).cxx_destruct;
- (id)description;
- (id)initWithCoder:(id)arg1;
- (void)encodeWithCoder:(id)arg1;
- (id)init;

@end

