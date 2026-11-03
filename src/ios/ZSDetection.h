#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Codes 0-8 reuse the OutSystems AppShield iOS shutdown codes so ExitOnURL landing pages keep
/// working. 41 is a ZamazentaShield extension shared with Android.
typedef NS_ENUM(NSInteger, ZSThreatCode) {
    ZSThreatJailbroken = 0,
    ZSThreatDebugger = 1,
    ZSThreatRepackaged = 2,
    ZSThreatScreenshot = 3,
    ZSThreatInjectedLibrary = 4,
    ZSThreatHookingFramework = 5,
    ZSThreatScreenRecording = 6,
    ZSThreatRunningOnMac = 7,
    ZSThreatSimulator = 8,
    ZSThreatScreenMirroring = 41,
};

@interface ZSDetection : NSObject

@property (nonatomic, readonly) ZSThreatCode code;
@property (nonatomic, readonly, copy) NSString *identifier;
@property (nonatomic, readonly, copy) NSString *summary;
@property (nonatomic, readonly, copy) NSArray<NSString *> *evidence;
/// Neutralised in place (content hidden) rather than by terminating the app.
@property (nonatomic, readonly) BOOL mitigatedInPlace;
@property (nonatomic, readonly) NSTimeInterval timestamp;

/// Returns nil when evidence is empty, so callers can add results unconditionally.
+ (nullable instancetype)detectionWithCode:(ZSThreatCode)code evidence:(NSArray<NSString *> *)evidence;

- (NSDictionary *)dictionaryWithAction:(NSString *)action;

@end

NS_ASSUME_NONNULL_END
