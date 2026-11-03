#import "ZSDetection.h"

static const NSUInteger ZSMaxEvidence = 12;

@implementation ZSDetection

+ (instancetype)detectionWithCode:(ZSThreatCode)code evidence:(NSArray<NSString *> *)evidence {
    if (evidence.count == 0) return nil;
    return [[self alloc] initWithCode:code evidence:evidence];
}

- (instancetype)initWithCode:(ZSThreatCode)code evidence:(NSArray<NSString *> *)evidence {
    if ((self = [super init])) {
        NSArray *unique = [[NSOrderedSet orderedSetWithArray:evidence] array];
        _code = code;
        _evidence = unique.count > ZSMaxEvidence ? [unique subarrayWithRange:NSMakeRange(0, ZSMaxEvidence)] : unique;
        _timestamp = [NSDate date].timeIntervalSince1970;
        switch (code) {
            case ZSThreatJailbroken:       _identifier = @"jailbroken"; _summary = @"Device is jailbroken"; break;
            case ZSThreatDebugger:         _identifier = @"debugger"; _summary = @"Application is being debugged"; break;
            case ZSThreatRepackaged:       _identifier = @"repackaged"; _summary = @"Application is modified or repackaged"; break;
            case ZSThreatScreenshot:       _identifier = @"screenshot"; _summary = @"A screenshot of the application was taken"; _mitigatedInPlace = YES; break;
            case ZSThreatInjectedLibrary:  _identifier = @"injected_library"; _summary = @"An injected library was found in the process"; break;
            case ZSThreatHookingFramework: _identifier = @"hooking_framework"; _summary = @"A hooking framework was found in the process"; break;
            case ZSThreatScreenRecording:  _identifier = @"screen_recording"; _summary = @"Screen recording or mirroring started"; _mitigatedInPlace = YES; break;
            case ZSThreatRunningOnMac:     _identifier = @"running_on_mac"; _summary = @"iOS app running on macOS"; break;
            case ZSThreatSimulator:        _identifier = @"simulator"; _summary = @"Running on a simulator"; break;
            case ZSThreatScreenMirroring:  _identifier = @"screen_mirroring"; _summary = @"App content routed to an external display"; _mitigatedInPlace = YES; break;
        }
    }
    return self;
}

- (NSDictionary *)dictionaryWithAction:(NSString *)action {
    return @{
        @"code": @(self.code),
        @"id": self.identifier ?: @"unknown",
        @"description": self.summary ?: @"",
        @"action": action,
        @"evidence": self.evidence,
        @"platform": @"ios",
        @"timestamp": @((long long)(self.timestamp * 1000)),
    };
}

@end
