//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSSet, SFActivityAdvertisement, SFActivityScanner, SFPeerDevice;

@protocol SFActivityScannerDelegate <NSObject>

@optional
- (void)activityScanner:(SFActivityScanner *)arg1 pairedDevicesChanged:(NSSet *)arg2;
- (void)activityScanner:(SFActivityScanner *)arg1 lostDeviceWithDevice:(SFPeerDevice *)arg2;
- (void)activityScanner:(SFActivityScanner *)arg1 foundDeviceWithDevice:(SFPeerDevice *)arg2;
- (void)activityScanner:(SFActivityScanner *)arg1 receivedAdvertisement:(SFActivityAdvertisement *)arg2;
@end
