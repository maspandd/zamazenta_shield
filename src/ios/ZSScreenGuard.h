#import <UIKit/UIKit.h>
#import "ZSDetection.h"

NS_ASSUME_NONNULL_BEGIN

/// Screen protections, all on the main thread:
/// - screenshots: content hosted in a secure-text-entry canvas, which iOS omits from captures;
/// - recording / AirPlay mirroring / external displays: a black shade over the app.
@interface ZSScreenGuard : NSObject

- (instancetype)initWithHostView:(UIView *)hostView
                  protectContent:(BOOL)protectContent
                        reporter:(void (^)(ZSDetection *detection))reporter NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

- (void)install;
- (void)uninstall;

/// Covers the app immediately (used just before termination).
- (void)blank;

@end

NS_ASSUME_NONNULL_END
