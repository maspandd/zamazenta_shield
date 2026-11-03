#import "ZSConfig.h"
#import <CommonCrypto/CommonDigest.h>

static BOOL ZSBool(NSDictionary *settings, NSString *key, BOOL fallback) {
    id value = settings[key.lowercaseString];
    if ([value isKindOfClass:[NSNumber class]]) return [value boolValue];
    if (![value isKindOfClass:[NSString class]] || [value length] == 0) return fallback;
    return [[value lowercaseString] isEqualToString:@"true"] || [value isEqualToString:@"1"];
}

static NSString *ZSString(NSDictionary *settings, NSString *key) {
    id value = settings[key.lowercaseString];
    return [value isKindOfClass:[NSString class]]
        ? [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]
        : @"";
}

@implementation ZSConfig

+ (instancetype)configWithSettings:(NSDictionary *)settings {
    return [[self alloc] initWithSettings:settings ?: @{}];
}

- (instancetype)initWithSettings:(NSDictionary *)s {
    if ((self = [super init])) {
        _disabled = ZSBool(s, @"DisableAppShielding", NO);
        _debugMode = ZSBool(s, @"AppShieldDebugMode", NO);
        _reportOnly = ZSBool(s, @"ZamazentaShieldReportOnly", NO);
        NSString *interval = ZSString(s, @"ZamazentaShieldRecheckIntervalMs");
        _recheckInterval = interval.length ? MAX(0, interval.doubleValue) / 1000.0 : 5.0;

        _allowJailbroken = ZSBool(s, @"AllowJailbrokenRootedDevices", NO);
        _allowScreenshot = ZSBool(s, @"AllowScreenshot", NO);
        _allowAppOnMac = ZSBool(s, @"AllowIOSAppOnMacOSX", NO);
        _blockEmulator = ZSBool(s, @"BlockEmulator", YES);

        _exitOnURL = ZSString(s, @"ExitOnURL");
        _signerFingerprints = [ZSConfig fingerprintsFromList:ZSString(s, @"ApplicationSignerCertificate")];
    }
    return self;
}

- (BOOL)enforcing {
    return !self.disabled && !self.debugMode && !self.reportOnly;
}

+ (NSSet<NSString *> *)fingerprintsFromList:(NSString *)raw {
    NSMutableSet *out = [NSMutableSet set];
    NSCharacterSet *separators = [NSCharacterSet characterSetWithCharactersInString:@";,"];
    NSRegularExpression *hexPattern = [NSRegularExpression regularExpressionWithPattern:@"^[0-9a-fA-F]{64}$" options:0 error:nil];
    for (NSString *token in [raw componentsSeparatedByCharactersInSet:separators]) {
        NSString *entry = [[token stringByReplacingOccurrencesOfString:@"-----BEGIN CERTIFICATE-----" withString:@""]
                           stringByReplacingOccurrencesOfString:@"-----END CERTIFICATE-----" withString:@""];
        entry = [[entry componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] componentsJoinedByString:@""];
        if (entry.length == 0) continue;
        NSString *hex = [entry stringByReplacingOccurrencesOfString:@":" withString:@""];
        if ([hexPattern numberOfMatchesInString:hex options:0 range:NSMakeRange(0, hex.length)] == 1) {
            [out addObject:hex.lowercaseString];
            continue;
        }
        NSData *bytes = [[NSData alloc] initWithBase64EncodedString:entry options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (bytes.length == CC_SHA256_DIGEST_LENGTH) {
            [out addObject:[self hexFromBytes:bytes]];
        } else if (bytes.length > 0) {
            [out addObject:[self sha256Hex:bytes]];
        }
    }
    return out;
}

+ (NSString *)sha256Hex:(NSData *)data {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return [self hexFromBytes:[NSData dataWithBytes:digest length:sizeof(digest)]];
}

+ (NSString *)hexFromBytes:(NSData *)data {
    const unsigned char *bytes = data.bytes;
    NSMutableString *hex = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) [hex appendFormat:@"%02x", bytes[i]];
    return hex;
}

- (NSDictionary *)dictionaryRepresentation {
    return @{
        @"DisableAppShielding": @(self.disabled),
        @"AppShieldDebugMode": @(self.debugMode),
        @"ZamazentaShieldReportOnly": @(self.reportOnly),
        @"ZamazentaShieldRecheckIntervalMs": @((long long)(self.recheckInterval * 1000)),
        @"AllowJailbrokenRootedDevices": @(self.allowJailbroken),
        @"AllowScreenshot": @(self.allowScreenshot),
        @"AllowIOSAppOnMacOSX": @(self.allowAppOnMac),
        @"BlockEmulator": @(self.blockEmulator),
        @"ExitOnURL": self.exitOnURL,
        @"ApplicationSignerCertificateCount": @(self.signerFingerprints.count),
    };
}

@end
