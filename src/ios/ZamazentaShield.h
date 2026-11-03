#import <Cordova/CDVPlugin.h>

/// Cordova entry point. Loaded at startup (onload=true): installs the screen guard, runs a full
/// scan, then re-runs the runtime checks (debugger, injected code, hooks) on a fixed interval.
@interface ZamazentaShield : CDVPlugin

- (void)getStatus:(CDVInvokedUrlCommand *)command;
- (void)check:(CDVInvokedUrlCommand *)command;
- (void)watch:(CDVInvokedUrlCommand *)command;

@end
