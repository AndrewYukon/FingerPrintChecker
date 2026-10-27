#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE (FingerPrintCheckerModule, NSObject)

RCT_EXTERN_METHOD(identify
                  : (NSDictionary *)args resolver
                  : (RCTPromiseResolveBlock)resolve rejecter
                  : (RCTPromiseRejectBlock)reject)

@end
