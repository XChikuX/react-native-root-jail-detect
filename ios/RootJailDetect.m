#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RootJailDetect, NSObject)

RCT_EXTERN_METHOD(isDeviceCompromised:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isSimulator:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isDebuggerAttached:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end