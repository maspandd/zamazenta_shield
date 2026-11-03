#import "ZamazentaShield.h"
#import "ZSConfig.h"
#import "ZSDetectors.h"
#import "ZSScreenGuard.h"

static NSString *const ZSVersion = @"0.1.0";
static NSString *const ZSActionExit = @"exit";
static NSString *const ZSActionReported = @"reported";
static NSString *const ZSActionMitigated = @"mitigated";
static const NSUInteger ZSMaxPendingEvents = 50;
static const NSTimeInterval ZSMitigationReportInterval = 5.0;
static const NSTimeInterval ZSExitDelay = 0.3;
static const NSTimeInterval ZSExitURLTimeout = 2.0;

@implementation ZamazentaShield {
    ZSConfig *_config;
    ZSScreenGuard *_screenGuard;
    dispatch_queue_t _scanQueue;
    dispatch_source_t _recheckTimer;

    NSString *_watchCallbackId;
    NSMutableArray<NSDictionary *> *_pendingEvents;
    NSArray<NSDictionary *> *_lastScan;
    NSMutableSet<NSString *> *_reported;
    NSMutableDictionary<NSNumber *, NSDate *> *_lastMitigation;
    BOOL _terminating;
}

- (void)pluginInitialize {
    _config = [ZSConfig configWithSettings:self.commandDelegate.settings];
    _pendingEvents = [NSMutableArray array];
    _lastScan = @[];
    _reported = [NSMutableSet set];
    _lastMitigation = [NSMutableDictionary dictionary];

    if (_config.disabled) {
        NSLog(@"[ZamazentaShield] DisableAppShielding=true; protections are off");
        return;
    }
    if (_config.enforcing) [ZSDetectors denyDebuggerAttach];

    __weak __typeof__(self) weakSelf = self;
    _screenGuard = [[ZSScreenGuard alloc] initWithHostView:self.viewController.view
                                            protectContent:!_config.allowScreenshot
                                                  reporter:^(ZSDetection *detection) { [weakSelf handle:detection]; }];
    [_screenGuard install];

    _scanQueue = dispatch_queue_create("com.zamazenta.shield.scan", DISPATCH_QUEUE_SERIAL);
    dispatch_async(_scanQueue, ^{ [weakSelf runScan:YES]; });

    if (_config.recheckInterval > 0) {
        uint64_t interval = (uint64_t)(_config.recheckInterval * NSEC_PER_SEC);
        _recheckTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _scanQueue);
        dispatch_source_set_timer(_recheckTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)interval), interval, interval / 10);
        dispatch_source_set_event_handler(_recheckTimer, ^{ [weakSelf runScan:NO]; });
        dispatch_resume(_recheckTimer);
    }

    [NSNotificationCenter.defaultCenter addObserver:self
                                           selector:@selector(willEnterForeground)
                                               name:UIApplicationWillEnterForegroundNotification
                                             object:nil];
}

- (void)dispose {
    [NSNotificationCenter.defaultCenter removeObserver:self];
    if (_recheckTimer) dispatch_source_cancel(_recheckTimer);
    [_screenGuard uninstall];
    [super dispose];
}

- (void)willEnterForeground {
    __weak __typeof__(self) weakSelf = self;
    dispatch_async(_scanQueue, ^{ [weakSelf runScan:YES]; });
}

#pragma mark - JS API

- (void)getStatus:(CDVInvokedUrlCommand *)command {
    NSArray *lastScan;
    @synchronized (self) { lastScan = _lastScan; }
    NSDictionary *status = @{
        @"platform": @"ios",
        @"version": ZSVersion,
        @"enabled": @(!_config.disabled),
        @"enforcing": @(_config.enforcing),
        @"detections": lastScan,
        @"config": [_config dictionaryRepresentation],
    };
    [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:status]
                                callbackId:command.callbackId];
}

- (void)check:(CDVInvokedUrlCommand *)command {
    if (_config.disabled) {
        [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsArray:@[]]
                                    callbackId:command.callbackId];
        return;
    }
    __weak __typeof__(self) weakSelf = self;
    dispatch_async(_scanQueue, ^{
        ZamazentaShield *strongSelf = weakSelf;
        if (!strongSelf) return;
        NSArray *results = [strongSelf runScan:YES];
        [strongSelf.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsArray:results]
                                          callbackId:command.callbackId];
    });
}

- (void)watch:(CDVInvokedUrlCommand *)command {
    NSArray *backlog;
    @synchronized (self) {
        _watchCallbackId = command.callbackId;
        backlog = [_pendingEvents copy];
        [_pendingEvents removeAllObjects];
    }
    CDVPluginResult *noResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_NO_RESULT];
    noResult.keepCallback = @YES;
    [self.commandDelegate sendPluginResult:noResult callbackId:command.callbackId];
    for (NSDictionary *event in backlog) [self send:event to:command.callbackId];
}

#pragma mark - Scanning and enforcement

/// Runs on _scanQueue. Returns the detections as event dictionaries.
- (NSArray<NSDictionary *> *)runScan:(BOOL)full {
    NSArray<ZSDetection *> *detections = full
        ? [ZSDetectors fullScanWithConfig:_config]
        : [ZSDetectors runtimeScanWithConfig:_config];
    NSMutableArray *snapshot = [NSMutableArray arrayWithCapacity:detections.count];
    for (ZSDetection *detection in detections) {
        [snapshot addObject:[detection dictionaryWithAction:[self actionFor:detection]]];
    }
    if (full) {
        @synchronized (self) { _lastScan = [snapshot copy]; }
    }
    for (ZSDetection *detection in detections) [self handle:detection];
    return snapshot;
}

- (NSString *)actionFor:(ZSDetection *)detection {
    if (detection.mitigatedInPlace) return ZSActionMitigated;
    return _config.enforcing ? ZSActionExit : ZSActionReported;
}

- (void)handle:(ZSDetection *)detection {
    NSString *action = [self actionFor:detection];
    @synchronized (self) {
        if ([action isEqualToString:ZSActionExit]) {
            if (_terminating) return;
            _terminating = YES;
        } else if ([action isEqualToString:ZSActionMitigated]) {
            NSDate *last = _lastMitigation[@(detection.code)];
            if (last && -last.timeIntervalSinceNow < ZSMitigationReportInterval) return;
            _lastMitigation[@(detection.code)] = [NSDate date];
        } else {
            NSString *key = [NSString stringWithFormat:@"%@%@", detection.identifier, detection.evidence];
            if ([_reported containsObject:key]) return;
            [_reported addObject:key];
        }
    }

    NSLog(@"[ZamazentaShield] %@ [%ld] -> %@ %@", detection.summary, (long)detection.code, action, detection.evidence);
    [self emit:[detection dictionaryWithAction:action]];
    if ([action isEqualToString:ZSActionExit]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self terminateFor:detection]; });
    }
}

- (void)terminateFor:(ZSDetection *)detection {
    [_screenGuard blank];
    void (^finish)(void) = ^{ exit(0); };
    NSURL *url = [self exitURLFor:detection];
    if (url) {
        [UIApplication.sharedApplication openURL:url options:@{} completionHandler:^(BOOL success) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(ZSExitDelay * NSEC_PER_SEC)), dispatch_get_main_queue(), finish);
        }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(ZSExitURLTimeout * NSEC_PER_SEC)), dispatch_get_main_queue(), finish);
    } else {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(ZSExitDelay * NSEC_PER_SEC)), dispatch_get_main_queue(), finish);
    }
}

/// Same parameters AppShield appends: reason, manufacturer, model, ios (OS version).
- (NSURL *)exitURLFor:(ZSDetection *)detection {
    if (_config.exitOnURL.length == 0) return nil;
    NSURLComponents *components = [NSURLComponents componentsWithString:_config.exitOnURL];
    NSString *scheme = components.scheme.lowercaseString;
    if (![scheme isEqualToString:@"https"] && ![scheme isEqualToString:@"http"]) {
        NSLog(@"[ZamazentaShield] ExitOnURL ignored: only http(s) URLs are opened");
        return nil;
    }
    components.queryItems = @[
        [NSURLQueryItem queryItemWithName:@"reason" value:[NSString stringWithFormat:@"%ld", (long)detection.code]],
        [NSURLQueryItem queryItemWithName:@"manufacturer" value:@"Apple"],
        [NSURLQueryItem queryItemWithName:@"model" value:[ZSDetectors deviceModel]],
        [NSURLQueryItem queryItemWithName:@"ios" value:UIDevice.currentDevice.systemVersion],
    ];
    return components.URL;
}

- (void)emit:(NSDictionary *)event {
    NSString *callbackId;
    @synchronized (self) {
        callbackId = _watchCallbackId;
        if (!callbackId) {
            if (_pendingEvents.count < ZSMaxPendingEvents) [_pendingEvents addObject:event];
            return;
        }
    }
    [self send:event to:callbackId];
}

- (void)send:(NSDictionary *)event to:(NSString *)callbackId {
    CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:event];
    result.keepCallback = @YES;
    [self.commandDelegate sendPluginResult:result callbackId:callbackId];
}

@end
