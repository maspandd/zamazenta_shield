# cordova-plugin-zamazenta-shield

Runtime app shielding for Cordova / OutSystems mobile apps on Android and iOS. It detects rooted or
jailbroken devices, debuggers, hooking frameworks, injected code, repackaging and emulators, and blocks
screenshots, screen recording, mirroring, tapjacking and overlay attacks.

It is a clean-room reimplementation of the feature set of **OutSystems AppShield**. It uses the
**same preference names, defaults, `ExitOnURL` contract and shutdown codes**, so an AppShield
Extensibility Configuration can be reused as-is. See [docs/APPSHIELD_ANALYSIS.md](docs/APPSHIELD_ANALYSIS.md)
for the feature-by-feature parity map and the limits of a source-level plugin compared with
AppShield's post-build binary shield.

## Install

```bash
cordova plugin add /path/to/zamazenta_shield
```

### OutSystems (O11 / ODC)

1. Remove the AppShield plugin from the app; both read the same preference names.
2. Create a wrapper module whose Extensibility Configuration points at a tagged version:
   `"plugin": { "url": "https://github.com/maspandd/zamazenta_shield.git#v0.1.0" }`. See
   [outsystems/extensibility-configuration.json](outsystems/extensibility-configuration.json).
3. For the first build, add `ZamazentaShieldReportOnly` = `true`. OutSystems debug builds are
   `debuggable`, which counts as repackaging, and the signing fingerprint is not known yet.
4. Generate the native build, install it, and check `adb logcat -s ZamazentaShield` or `getStatus()`.
   `"native": true` means libzshield loaded.
5. Read the signer with `apksigner verify --print-certs app.apk`, set `ApplicationSignerCertificate`
   (add the Play App Signing key if you publish through Play), then turn report-only off.

The plugin needs MABS with cordova-android ≥ 12. If MABS cannot build the native layer, set
`ZamazentaShieldNativeBuild` = `false` (see below).

Requirements: cordova-android ≥ 12 (minSdk 24), cordova-ios ≥ 6. The Android build compiles a native
library, so the build machine needs the Android NDK and CMake. AGP downloads its default versions if
SDK licences are accepted. Tested with cordova-android 15.1.0 (AGP 8.10.1, NDK 27.0.12077973).

## Android native layer (libzshield)

The Java checks can be hooked or patched. A C library, built from `src/android/cpp` through
`externalNativeBuild`, adds a second layer that is harder to blind:

- **Raw syscalls** on arm64 and x86_64 (inline `svc`/`syscall`). Libc hooks used by root hiders and
  anti-Frida scripts (`open`, `access`, `strstr`, …) never see the native root, tracer and Frida checks.
- **Inline-hook detection** (code 6). The first 16 bytes of ~30 commonly hooked libc/libdl functions,
  and of the library's own check functions, are compared with the bytes in the file they were mapped
  from. This catches Frida `Interceptor`, Dobby and Substrate-style trampolines, and debugger breakpoints.
- **Frida in memory** (code 22). Agent strings are searched for in memfd-backed mappings, which catches
  renamed builds. Glib thread names and injector fds are also checked.
- **Memory-scanner detection** (code 42, `BlockMemoryScan`). An inotify watch on `/proc/self/mem`
  fires when a scanner or dumper opens it (GameGuardian, `dd`, memory dumpers).
- **Anti-tracing** (`BlockCodeTraceDetection`). Native `TracerPid` polling, plus `PR_SET_DUMPABLE 0`
  when enforcing, so non-root processes can no longer `ptrace` the app or read its memory.
- **APK signature** (code 1). The v2/v3/v3.1 signing block is read straight from the installed APK
  (path taken from `/proc/self/maps`) and hashed with a built-in SHA-256, so a hooked PackageManager
  cannot fake the signer. The scheme is chosen by API level to defeat block splicing.
- **Watchdog + fail-safe.** A native thread repeats the runtime checks every
  `ZamazentaShieldRecheckIntervalMs`, independent of the Java scheduler. When enforcing, any native
  detection arms a 3 s timer that ends the process with a raw `exit_group`, even if the Java enforcer
  was patched out.

If the library is missing at runtime, the app reports `REPACKAGED` (`native:libzshield missing`), unless
`ZamazentaShieldRequireNative` is `false`. Natives are bound with `RegisterNatives` (only `JNI_OnLoad`
is exported), and keep rules ship in `proguard-zshield.pro`.

If the build server cannot build native code, set `ZamazentaShieldNativeBuild` to `false`. The library is
then not built, the app does not expect it, and only the Java/iOS protections run.

> AGP allows one `externalNativeBuild` per module. If another plugin or the app already declares one,
> merge `src/main/cpp/zshield/CMakeLists.txt` into it with `add_subdirectory`.

## Behaviour

At startup (`onload=true`) the plugin installs the screen guards and runs a full scan in the background.
The volatile checks (debugger, hooks, injected code, VPN) are re-run every
`ZamazentaShieldRecheckIntervalMs`. A full scan also runs whenever the app returns to the foreground.

On a blocking detection, the plugin does what AppShield does: it hides the UI, opens `ExitOnURL` (if set) with
`?reason=<code>&manufacturer=…&model=…&ANDROID=<api>` (`ios=<version>` on iOS), and terminates the
process. The base URL must not carry its own query parameters, same as AppShield.

Some threats are **mitigated in place** instead and the app keeps running. These are tapjacking (touch
dropped), screen recording or mirroring (content blanked) and screenshots on iOS (content omitted from the
capture).

## Configuration

Set these as Cordova `<preference>`s in `config.xml`, or in the `preferences` section of the OutSystems
Extensibility Configuration.

| Preference | Default | Platform | Effect |
|---|---|---|---|
| `DisableAppShielding` | false | both | Turn everything off |
| `AppShieldDebugMode` | false | both | Report only. Debugger checks and `PT_DENY_ATTACH` off, `debuggable` APK allowed |
| `ZamazentaShieldReportOnly` | false | both | Report only, with all checks active (for a monitoring rollout) |
| `ZamazentaShieldRecheckIntervalMs` | 5000 | both | Periodic runtime re-check, `0` disables |
| `ExitOnURL` | – | both | http(s) page opened before exit |
| `ApplicationSignerCertificate` | – | both | Allowed signing certs, separated by `;`. Base64 DER, PEM, or SHA-256 hex |
| `AllowJailbrokenRootedDevices` | false | both | Skip root/jailbreak detection |
| `AllowScreenshot` | false | both | Allow screenshots/recording |
| `BlockEmulator` | true | both | Block emulators/simulators |
| `AllowIOSAppOnMacOSX` | false | iOS | Allow running on Apple-silicon Macs |
| `AllowPrivateSpace` | true | Android | `false` blocks Private Space / work profile |
| `AllowTapjacking` | true | Android | `false` enables tapjacking protection |
| `BlockDeveloperMode` | false | Android | Block when developer options/ADB are on |
| `BlockUnlockedBootloader` | true | Android | Block unlocked bootloaders |
| `BlockNonSystemOverlays` | true | Android 12+ | Hide third-party overlays over the app |
| `BlockEmulatedInput` | false | Android | Block injected/virtual touch input |
| `BlockScreenMirroring` | false | Android | Blank secondary displays (always on for iOS) |
| `BlockVPN` | false | Android | Block when a VPN is active |
| `BlockUntrustedKeyboards` | false | Android | Block non-system IMEs not listed in `AddTrustedKeyboardSigner` |
| `BlockUntrustedScreenreaders` | false | Android | Block non-system accessibility services not listed in `AddTrustedScreenReaderSigner` |
| `BlockHiddenSEPolicyArtifacts` | false | Android | Treat permissive SELinux as root |
| `BlockMemoryScan` | true | Android | Block when `/proc/self/mem` is opened by another process |
| `BlockCodeTraceDetection` | true | Android | Native tracer polling and `PR_SET_DUMPABLE 0` hardening |
| `ZamazentaShieldRequireNative` | true | Android | Treat a missing `libzshield.so` as repackaging |
| `ZamazentaShieldNativeBuild` | true | Android | `false` skips building the native layer (no NDK/CMake on the build server); Java protections still run |

### Signing certificates

- **Android, Play distribution:** list the **App Signing key** fingerprint from Play Console → App
  integrity, plus your upload key if you install directly. Without this setting the repackaging check only
  catches the `debuggable` flag, and it logs a warning.
- **iOS:** App Store/TestFlight builds are verified through FairPlay encryption and need no setting.
  Development, ad-hoc and enterprise builds compare the certificates in `embedded.mobileprovision`
  against the list.

> Debug builds are `debuggable`, so they exit with code 1 unless `AppShieldDebugMode` is `true`. This
> matches AppShield's own requirement.

## JavaScript API

```js
document.addEventListener('deviceready', async () => {
  const shield = cordova.plugins.ZamazentaShield;

  const off = shield.onThreat((event) => {
    // { code, id, description, action: 'exit'|'reported'|'mitigated', evidence: [...], platform, timestamp }
    console.warn('threat', event);
  });

  const status = await shield.getStatus(); // config, enforcing flag, last full-scan detections
  const found = await shield.check();      // run a full scan now (enforcement still applies)
});
```

Events raised before `onThreat` subscribes (including the startup scan) are buffered natively, up to 50,
and delivered on subscribe. Typings are in [types/index.d.ts](types/index.d.ts).

## Threat codes

| Code | Android | iOS |
|---|---|---|
| 0 | Rooted | Jailbroken |
| 1 | Repackaged | Debugger |
| 2 | Emulator | Repackaged |
| 3 | Java debugger | Screenshot taken *(mitigated)* |
| 4 | Untrusted keyboard | Injected library |
| 5 | Untrusted screen reader | Hooking framework |
| 6 | Native code hooks | Screen recording *(mitigated)* |
| 7 | – | Running on macOS |
| 8 | – | Simulator |
| 9 | Native debugger | – |
| 22 | Hooking framework | – |
| 29 | Virtual-space app | – |
| 31 | Emulated input | – |
| 32 | Private Space / work profile | – |
| 33 | Unlocked bootloader | – |
| 34 | Tapjacking *(mitigated)* | – |
| 35 | Code injection | – |
| 37 | VPN | – |
| 40 | Developer mode *(extension)* | – |
| 41 | Screen mirroring *(extension, mitigated)* | Screen mirroring *(extension, mitigated)* |
| 42 | Memory scanning *(extension)* | – |

## Hardening the plugin itself

A source-level plugin can be patched out of a repackaged app, so layer it:

1. Keep R8 on. The shipped rules only keep the Cordova entry class and the JNI bridge.
2. Pair it with server-side attestation (Play Integrity API / App Attest). Client checks raise the cost of
   attack, and the server is what enforces.
3. Treat `evidence` strings as diagnostics. They are not a stable API.
