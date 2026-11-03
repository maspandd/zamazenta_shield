#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Runtime policy from config.xml preferences, using the OutSystems AppShield key names and defaults.
@interface ZSConfig : NSObject

@property (nonatomic, readonly) BOOL disabled;
@property (nonatomic, readonly) BOOL debugMode;
@property (nonatomic, readonly) BOOL reportOnly;
@property (nonatomic, readonly) NSTimeInterval recheckInterval;

@property (nonatomic, readonly) BOOL allowJailbroken;
@property (nonatomic, readonly) BOOL allowScreenshot;
@property (nonatomic, readonly) BOOL allowAppOnMac;
@property (nonatomic, readonly) BOOL blockEmulator;

@property (nonatomic, readonly, copy) NSString *exitOnURL;
@property (nonatomic, readonly, copy) NSSet<NSString *> *signerFingerprints;

@property (nonatomic, readonly) BOOL enforcing;

/// @param settings CDVCommandDelegate settings (keys are lower-cased by Cordova).
+ (instancetype)configWithSettings:(NSDictionary *)settings;

/// Lower-case SHA-256 hex fingerprints from a ';' or ',' separated list of hex fingerprints,
/// Base64 SHA-256 digests, or Base64/PEM DER certificates.
+ (NSSet<NSString *> *)fingerprintsFromList:(nullable NSString *)raw;

+ (NSString *)sha256Hex:(NSData *)data;

- (NSDictionary *)dictionaryRepresentation;

@end

NS_ASSUME_NONNULL_END
