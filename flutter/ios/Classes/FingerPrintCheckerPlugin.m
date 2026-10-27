#import "FingerPrintCheckerPlugin.h"
#if __has_include(<fingerprintchecker/fingerprintchecker-Swift.h>)
#import <fingerprintchecker/fingerprintchecker-Swift.h>
#else
#import "fingerprintchecker-Swift.h"
#endif

@implementation FingerPrintCheckerPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar> *)registrar {
  [SwiftFingerPrintCheckerPlugin registerWithRegistrar:registrar];
}
@end
