#import "ZSDetectors.h"
#import <UIKit/UIKit.h>
#import <TargetConditionals.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <netinet/in.h>
#import <sys/select.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>

#pragma mark - Indicator lists

static NSArray<NSString *> *ZSJailbreakPaths(void) {
    return @[
        @"/Applications/Cydia.app", @"/Applications/Sileo.app", @"/Applications/Zebra.app",
        @"/Applications/Installer.app", @"/Applications/blackra1n.app", @"/Applications/FakeCarrier.app",
        @"/Applications/Icy.app", @"/Applications/IntelliScreen.app", @"/Applications/MxTube.app",
        @"/Applications/RockApp.app", @"/Applications/SBSettings.app", @"/Applications/WinterBoard.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib", @"/Library/MobileSubstrate/DynamicLibraries",
        @"/Library/PreferenceBundles/LibertyPref.bundle", @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        @"/usr/sbin/sshd", @"/usr/bin/sshd", @"/usr/libexec/sftp-server", @"/usr/libexec/ssh-keysign",
        @"/etc/ssh/sshd_config", @"/bin/bash", @"/etc/apt", @"/private/var/lib/apt", @"/private/var/lib/cydia",
        @"/private/var/stash", @"/private/var/tmp/cydia.log", @"/var/cache/apt", @"/var/lib/cydia", @"/var/lib/dpkg",
        @"/usr/bin/cycript", @"/usr/local/bin/cycript", @"/usr/lib/libcycript.dylib", @"/usr/lib/libjailbreak.dylib",
        @"/usr/lib/libhooker.dylib", @"/usr/lib/libsubstitute.dylib", @"/usr/lib/substrate", @"/usr/lib/ellekit",
        @"/usr/lib/TweakInject", @"/usr/share/jailbreak/injectme.plist", @"/var/jb", @"/var/binpack",
        @"/var/lib/undecimus", @"/var/checkra1n.dmg", @"/.bootstrapped_electra", @"/.installed_unc0ver",
        @"/.installed_odyssey", @"/private/preboot/procursus",
    ];
}

static NSArray<NSString *> *ZSJailbreakSchemes(void) {
    // Must also be listed under LSApplicationQueriesSchemes (plugin.xml) or canOpenURL always says NO.
    return @[@"cydia", @"sileo", @"zbra", @"filza", @"undecimus", @"activator"];
}

static NSArray<NSString *> *ZSHookImageMarkers(void) {
    return @[
        @"frida", @"cynject", @"libcycript", @"substrate", @"substitute", @"libhooker", @"ellekit",
        @"tweakinject", @"sslkillswitch", @"/shadow.dylib", @"libblackjack", @"libertylite", @"flyjb",
        @"systemhook", @"rocketbootstrap",
    ];
}

#if !TARGET_OS_SIMULATOR
/// Locations the dynamic loader legitimately maps code from on a stock device.
static NSArray<NSString *> *ZSTrustedImagePrefixes(void) {
    return @[@"/usr/lib/", @"/System/", @"/Developer/", @"/preboot/Cryptexes/", @"/usr/libexec/"];
}
#endif

static const in_port_t ZSFridaPorts[] = {27042, 27047};

#pragma mark - Low-level probes

static BOOL ZSPathExists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 || lstat(path, &st) == 0;
}

static NSString *ZSStripPrivate(NSString *path) {
    return [path hasPrefix:@"/private/"] ? [path substringFromIndex:8] : path;
}

static BOOL ZSIsTraced(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return NO;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

static BOOL ZSLocalPortOpen(in_port_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NO;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    BOOL open = NO;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        open = YES;
    } else if (errno == EINPROGRESS) {
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(fd, &writable);
        struct timeval timeout = {0, 100000};
        if (select(fd + 1, NULL, &writable, NULL, &timeout) == 1) {
            int error = 0;
            socklen_t length = sizeof(error);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length);
            open = error == 0;
        }
    }
    close(fd);
    return open;
}

#if !TARGET_OS_SIMULATOR
/// cryptid of the main executable: 1 = FairPlay-encrypted (App Store / TestFlight), 0 = plain, -1 = no info.
static int ZSMainImageCryptId(void) {
    const struct mach_header *header = _dyld_get_image_header(0);
    if (!header || header->filetype != MH_EXECUTE) return -1;
    BOOL is64 = header->magic == MH_MAGIC_64;
    const uint8_t *cursor = (const uint8_t *)header + (is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmd == LC_ENCRYPTION_INFO || command->cmd == LC_ENCRYPTION_INFO_64) {
            // cryptid sits at the same offset in the 32- and 64-bit variants.
            return (int)((const struct encryption_info_command *)command)->cryptid;
        }
        cursor += command->cmdsize;
    }
    return -1;
}

/// SHA-256 fingerprints of DeveloperCertificates in embedded.mobileprovision, or nil when the
/// bundle has no profile (App Store builds strip it).
static NSArray<NSString *> *ZSProvisionedCertificateFingerprints(void) {
    NSString *path = [NSBundle.mainBundle pathForResource:@"embedded" ofType:@"mobileprovision"];
    NSData *data = path ? [NSData dataWithContentsOfFile:path] : nil;
    if (!data) return nil;

    // The profile is a CMS envelope around an XML plist; slice the plist out without parsing CMS.
    NSString *raw = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
    NSRange start = [raw rangeOfString:@"<?xml"];
    NSRange end = [raw rangeOfString:@"</plist>"];
    if (start.location == NSNotFound || end.location == NSNotFound) return @[];
    NSString *xml = [raw substringWithRange:NSMakeRange(start.location, NSMaxRange(end) - start.location)];
    NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:[xml dataUsingEncoding:NSISOLatin1StringEncoding]
                                                                    options:NSPropertyListImmutable
                                                                     format:NULL
                                                                      error:NULL];
    NSMutableArray *fingerprints = [NSMutableArray array];
    for (id certificate in plist[@"DeveloperCertificates"]) {
        if ([certificate isKindOfClass:[NSData class]]) [fingerprints addObject:[ZSConfig sha256Hex:certificate]];
    }
    return fingerprints;
}
#endif

#pragma mark - Detectors

@implementation ZSDetectors

+ (NSArray<ZSDetection *> *)fullScanWithConfig:(ZSConfig *)config {
    NSMutableArray<ZSDetection *> *out = [[self runtimeScanWithConfig:config] mutableCopy];
    if (!config.allowJailbroken) [self addObject:[self jailbreak] to:out];
    [self addObject:[self repackagingWithConfig:config] to:out];
    if (!config.allowAppOnMac) [self addObject:[self runningOnMac] to:out];
    if (config.blockEmulator) [self addObject:[self simulator] to:out];
    return out;
}

+ (NSArray<ZSDetection *> *)runtimeScanWithConfig:(ZSConfig *)config {
    NSMutableArray<ZSDetection *> *out = [NSMutableArray array];
    if (!config.debugMode) [self addObject:[self debugger] to:out];
    [self addImageDetectionsTo:out];
    return out;
}

+ (void)addObject:(ZSDetection *)detection to:(NSMutableArray *)out {
    if (detection) [out addObject:detection];
}

+ (ZSDetection *)jailbreak {
    NSMutableArray *evidence = [NSMutableArray array];
    for (NSString *path in ZSJailbreakPaths()) {
        if (ZSPathExists(path.fileSystemRepresentation)) [evidence addObject:[@"file:" stringByAppendingString:path]];
    }

    struct stat st;
    if (lstat("/Applications", &st) == 0 && S_ISLNK(st.st_mode)) [evidence addObject:@"symlink:/Applications"];

    // A sandboxed app cannot write outside its container.
    NSString *probe = [NSString stringWithFormat:@"/private/zs-%@", NSUUID.UUID.UUIDString];
    if ([@"x" writeToFile:probe atomically:NO encoding:NSUTF8StringEncoding error:NULL]) {
        [evidence addObject:@"sandbox:writable-root"];
        [NSFileManager.defaultManager removeItemAtPath:probe error:NULL];
    }

    __block NSMutableArray *schemes = [NSMutableArray array];
    void (^probeSchemes)(void) = ^{
        for (NSString *scheme in ZSJailbreakSchemes()) {
            NSURL *url = [NSURL URLWithString:[scheme stringByAppendingString:@"://"]];
            if ([UIApplication.sharedApplication canOpenURL:url]) [schemes addObject:[@"scheme:" stringByAppendingString:scheme]];
        }
    };
    if (NSThread.isMainThread) probeSchemes(); else dispatch_sync(dispatch_get_main_queue(), probeSchemes);
    [evidence addObjectsFromArray:schemes];

    return [ZSDetection detectionWithCode:ZSThreatJailbroken evidence:evidence];
}

+ (ZSDetection *)debugger {
    NSMutableArray *evidence = [NSMutableArray array];
    if (ZSIsTraced()) [evidence addObject:@"sysctl:P_TRACED"];
    return [ZSDetection detectionWithCode:ZSThreatDebugger evidence:evidence];
}

+ (void)addImageDetectionsTo:(NSMutableArray *)out {
    NSMutableArray *hooks = [NSMutableArray array];
    NSMutableArray *injected = [NSMutableArray array];
#if !TARGET_OS_SIMULATOR
    NSString *bundlePath = ZSStripPrivate(NSBundle.mainBundle.bundlePath);
#endif

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *path = ZSStripPrivate(@(name));
        NSString *lower = path.lowercaseString;
        BOOL hooked = NO;
        for (NSString *marker in ZSHookImageMarkers()) {
            if ([lower containsString:marker]) { hooked = YES; break; }
        }
        if (hooked) {
            [hooks addObject:[@"image:" stringByAppendingString:path]];
            continue;
        }
#if !TARGET_OS_SIMULATOR
        BOOL trusted = [path hasPrefix:bundlePath];
        for (NSString *prefix in ZSTrustedImagePrefixes()) trusted = trusted || [path hasPrefix:prefix];
        if (!trusted) [injected addObject:[@"image:" stringByAppendingString:path]];
#endif
    }

    if (getenv("DYLD_INSERT_LIBRARIES")) [injected addObject:@"env:DYLD_INSERT_LIBRARIES"];
    for (size_t i = 0; i < sizeof(ZSFridaPorts) / sizeof(ZSFridaPorts[0]); i++) {
        if (ZSLocalPortOpen(ZSFridaPorts[i])) [hooks addObject:[NSString stringWithFormat:@"port:127.0.0.1:%d", ZSFridaPorts[i]]];
    }

    [self addObject:[ZSDetection detectionWithCode:ZSThreatHookingFramework evidence:hooks] to:out];
    [self addObject:[ZSDetection detectionWithCode:ZSThreatInjectedLibrary evidence:injected] to:out];
}

+ (ZSDetection *)repackagingWithConfig:(ZSConfig *)config {
#if TARGET_OS_SIMULATOR
    return nil;
#else
    NSMutableArray *evidence = [NSMutableArray array];
    NSArray<NSString *> *provisioned = ZSProvisionedCertificateFingerprints();
    if (provisioned) {
        // Development, ad-hoc or enterprise build: the profile must name one of our certificates.
        if (config.signerFingerprints.count == 0) {
            if (!config.debugMode) NSLog(@"[ZamazentaShield] ApplicationSignerCertificate not set; profile signer check skipped");
        } else if (![config.signerFingerprints intersectsSet:[NSSet setWithArray:provisioned]]) {
            for (NSString *fingerprint in provisioned) [evidence addObject:[@"profile-cert:" stringByAppendingString:fingerprint]];
            if (provisioned.count == 0) [evidence addObject:@"profile:unreadable"];
        }
    } else if (ZSMainImageCryptId() == 0) {
        // No profile means an App Store build, which Apple always ships encrypted. A plain
        // binary without a profile was decrypted and re-signed.
        [evidence addObject:@"macho:cryptid=0"];
    }
    return [ZSDetection detectionWithCode:ZSThreatRepackaged evidence:evidence];
#endif
}

+ (ZSDetection *)runningOnMac {
    NSMutableArray *evidence = [NSMutableArray array];
    if (@available(iOS 14.0, *)) {
        if (NSProcessInfo.processInfo.isiOSAppOnMac) [evidence addObject:@"processInfo:isiOSAppOnMac"];
    }
    return [ZSDetection detectionWithCode:ZSThreatRunningOnMac evidence:evidence];
}

+ (ZSDetection *)simulator {
    NSMutableArray *evidence = [NSMutableArray array];
#if TARGET_OS_SIMULATOR
    [evidence addObject:@"build:simulator"];
#endif
    if (NSProcessInfo.processInfo.environment[@"SIMULATOR_DEVICE_NAME"]) [evidence addObject:@"env:SIMULATOR_DEVICE_NAME"];
    return [ZSDetection detectionWithCode:ZSThreatSimulator evidence:evidence];
}

+ (void)denyDebuggerAttach {
#if !TARGET_OS_SIMULATOR
    typedef int (*ZSPtrace)(int request, pid_t pid, caddr_t addr, int data);
    ZSPtrace ptraceFn = (ZSPtrace)dlsym(RTLD_DEFAULT, "ptrace");
    if (ptraceFn) ptraceFn(31 /* PT_DENY_ATTACH */, 0, 0, 0);
#endif
}

+ (NSString *)deviceModel {
    size_t size = 0;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    if (size == 0) return UIDevice.currentDevice.model;
    char *machine = malloc(size);
    sysctlbyname("hw.machine", machine, &size, NULL, 0);
    NSString *model = @(machine);
    free(machine);
    return model;
}

@end
