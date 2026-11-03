#import "ZSScreenGuard.h"

@implementation ZSScreenGuard {
    __weak UIView *_host;
    BOOL _protectContent;
    void (^_reporter)(ZSDetection *);
    UITextField *_secureField;
    UIView *_secureCanvas;
    UIView *_shade;
    BOOL _blanked;
}

- (instancetype)initWithHostView:(UIView *)hostView
                  protectContent:(BOOL)protectContent
                        reporter:(void (^)(ZSDetection *))reporter {
    if ((self = [super init])) {
        _host = hostView;
        _protectContent = protectContent;
        _reporter = [reporter copy];
    }
    return self;
}

- (void)install {
    if (_protectContent) [self installSecureCanvas];

    NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
    [center addObserver:self selector:@selector(refreshCaptureState) name:UIScreenCapturedDidChangeNotification object:nil];
    [center addObserver:self selector:@selector(refreshCaptureState) name:UIScreenDidConnectNotification object:nil];
    [center addObserver:self selector:@selector(refreshCaptureState) name:UIScreenDidDisconnectNotification object:nil];
    if (_protectContent) {
        [center addObserver:self selector:@selector(screenshotTaken) name:UIApplicationUserDidTakeScreenshotNotification object:nil];
    }
    [self refreshCaptureState];
}

- (void)uninstall {
    [NSNotificationCenter.defaultCenter removeObserver:self];
    UIView *host = _host;
    if (_secureCanvas && host) {
        for (UIView *subview in [_secureCanvas.subviews copy]) [host insertSubview:subview belowSubview:_secureCanvas];
        [_secureCanvas removeFromSuperview];
    }
    _secureCanvas = nil;
    _secureField = nil;
    [self setShadeVisible:NO];
}

- (void)blank {
    _blanked = YES;
    [self setShadeVisible:YES];
}

#pragma mark - Screenshot protection

/// Re-parents the host's content into the canvas view of a secure UITextField. iOS renders that
/// canvas normally on screen but leaves it out of screenshots, recordings and the app switcher.
/// The canvas class is private, so this degrades to "no protection" if UIKit changes.
- (void)installSecureCanvas {
    UIView *host = _host;
    if (!host) return;
    UITextField *field = [[UITextField alloc] initWithFrame:host.bounds];
    field.secureTextEntry = YES;
    [field layoutIfNeeded];

    UIView *canvas = nil;
    for (UIView *subview in field.subviews) {
        if ([NSStringFromClass(subview.class) containsString:@"Canvas"]) { canvas = subview; break; }
    }
    if (!canvas) {
        NSLog(@"[ZamazentaShield] Secure canvas unavailable on this iOS version; screenshots are not blocked");
        return;
    }

    _secureField = field;
    [canvas removeFromSuperview];
    canvas.frame = host.bounds;
    canvas.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    canvas.userInteractionEnabled = YES;
    for (UIView *subview in [host.subviews copy]) [canvas addSubview:subview];
    [host addSubview:canvas];
    _secureCanvas = canvas;
}

- (void)screenshotTaken {
    NSString *evidence = _secureCanvas ? @"notification:userDidTakeScreenshot (content hidden)" : @"notification:userDidTakeScreenshot";
    [self report:ZSThreatScreenshot evidence:@[evidence]];
}

#pragma mark - Recording / mirroring

- (void)refreshCaptureState {
    if (_blanked) return;
    BOOL external = UIScreen.screens.count > 1;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    BOOL captured = UIScreen.mainScreen.isCaptured;
#pragma clang diagnostic pop
    // isCaptured covers both recording and AirPlay mirroring; iOS does not say which.
    BOOL hide = external || (captured && _protectContent);
    BOOL wasHidden = _shade != nil;
    [self setShadeVisible:hide];
    if (hide && !wasHidden) {
        if (external) {
            [self report:ZSThreatScreenMirroring evidence:@[[NSString stringWithFormat:@"screens:%lu", (unsigned long)UIScreen.screens.count]]];
        } else {
            [self report:ZSThreatScreenRecording evidence:@[@"UIScreen.isCaptured"]];
        }
    }
}

- (void)setShadeVisible:(BOOL)visible {
    UIView *host = _host;
    if (visible) {
        if (!host) return;
        if (!_shade) {
            _shade = [[UIView alloc] initWithFrame:host.bounds];
            _shade.backgroundColor = UIColor.blackColor;
            _shade.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
            _shade.userInteractionEnabled = YES;
        }
        [host addSubview:_shade];
        [host bringSubviewToFront:_shade];
    } else {
        [_shade removeFromSuperview];
        _shade = nil;
    }
}

- (void)report:(ZSThreatCode)code evidence:(NSArray<NSString *> *)evidence {
    ZSDetection *detection = [ZSDetection detectionWithCode:code evidence:evidence];
    if (detection && _reporter) _reporter(detection);
}

@end
