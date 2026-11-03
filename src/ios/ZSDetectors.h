#import <Foundation/Foundation.h>
#import "ZSConfig.h"
#import "ZSDetection.h"

NS_ASSUME_NONNULL_BEGIN

@interface ZSDetectors : NSObject

/// Every check the configuration enables. Safe to call off the main thread.
+ (NSArray<ZSDetection *> *)fullScanWithConfig:(ZSConfig *)config;

/// The volatile subset (debugger, injected code, hooking frameworks) for periodic re-checks.
+ (NSArray<ZSDetection *> *)runtimeScanWithConfig:(ZSConfig *)config;

/// PT_DENY_ATTACH: a debugger attaching later makes the kernel kill the process.
+ (void)denyDebuggerAttach;

/// Hardware identifier such as "iPhone15,2".
+ (NSString *)deviceModel;

@end

NS_ASSUME_NONNULL_END
