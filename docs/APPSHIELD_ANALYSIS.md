# OutSystems AppShield: analysis and parity map

## What AppShield is

OutSystems AppShield (Forge asset 9379, O11, current 1.21.0) is a paid add-on. The Forge module itself
holds no protection logic. It is a licence and configuration carrier. The protection is applied by
**MABS (6.3+) as a post-build "shield" phase**: the compiled APK/IPA is rewritten and wrapped with a
native runtime that runs before the app's own code. That is why it reports native shutdown codes,
offers native code obfuscation and needs no JavaScript API. (Inference: the shutdown-code taxonomy and
feature set match a commercial binary-shielding vendor's SDK, licensed rather than built in-house.)

Consequences for "reverse engineering into a Cordova plugin":

- There is no source to port. The Forge OML has no protection code, and the shielding engine is
  proprietary, licensed and obfuscated by design. Decompiling it would breach its licence and would not
  give maintainable code.
- This repository is therefore a **clean-room reimplementation** built from AppShield's public
  documentation: the same configuration keys, defaults, exit-URL contract and shutdown codes, implemented
  with original code using well-known detection techniques.
- A source-level Cordova plugin is weaker than a post-build binary shield. Its Java/Obj-C can itself
  be patched out of a repackaged app. See "Gaps" below.

Sources: OutSystems docs, "Harden the protection of mobile apps with AppShield" (O11),
"Troubleshooting AppShield crashes" (O11), ODC docs repo `src/eap/security/app-shield/*`.

## Configuration compatibility

Every AppShield key below is read from `config.xml` preferences, which is where OutSystems
Extensibility Configuration `preferences` land. An existing AppShield block can be reused unchanged.

| Key | Default | Status here |
|---|---|---|
| DisableAppShielding | false | ✅ |
| AllowJailbrokenRootedDevices | false | ✅ |
| AllowScreenshot | false | ✅ |
| AllowPrivateSpace | true | ✅ Android |
| AllowTapjacking | true | ✅ Android |
| AllowIOSAppOnMacOSX | false | ✅ iOS |
| AppShieldDebugMode | false | ✅ (here: report-only + debugger checks off; see README) |
| BlockDeveloperMode | false | ✅ Android · ❌ iOS (no public API) |
| BlockEmulator | true | ✅ |
| BlockUntrustedKeyboards / AddTrustedKeyboardSigner | false | ✅ Android |
| BlockUntrustedScreenreaders / AddTrustedScreenReaderSigner | false | ✅ Android |
| BlockUnlockedBootloader | true | ✅ Android |
| BlockNonSystemOverlays | true | ✅ Android 12+ (`setHideOverlayWindows`) |
| BlockEmulatedInput | false | ✅ Android |
| BlockScreenMirroring | false | ✅ Android · iOS always on (as in AppShield) |
| BlockVPN | false | ✅ Android |
| BlockHiddenSEPolicyArtifacts | false | ⚠️ Android, SELinux-permissive check only |
| ExitOnURL | – | ✅ same `reason`, `manufacturer`, `model`, `ANDROID`/`ios` params |
| ApplicationSignerCertificate | – | ✅ (also accepts SHA-256 hex fingerprints) |
| BlockMemoryScan | true | ✅ Android: native inotify watch on `/proc/self/mem` |
| BlockCodeTraceDetection | true | ✅ Android: native TracerPid polling, prologue checks, `PR_SET_DUMPABLE 0` |
| RemoveQueryAllPackagesPermission | true | ✅ by design: plugin never requests QUERY_ALL_PACKAGES |
| AppShieldObfuscationRules | – | ❌ build-time; use R8/ProGuard instead |

## Feature parity

| AppShield feature | Platform | Implementation | Code |
|---|---|---|---|
| Root detection | Android | su paths/PATH, root-manager packages, test-keys, `ro.secure`/`ro.debuggable`, Magisk/KernelSU mounts, rw `/system` | 0 |
| Jailbreak detection | iOS | ~50 artifact paths incl. rootless `/var/jb`, `/Applications` symlink, sandbox write probe, `canOpenURL` schemes | 0 |
| Repackaging | Android | APK signer SHA-256 vs `ApplicationSignerCertificate`; `debuggable` flag in non-debug builds | 1 |
| Repackaging | iOS | `embedded.mobileprovision` certs vs configured list; App Store builds: FairPlay `cryptid` must be 1 | 2 |
| Emulator | Android | qemu/Genymotion/Nox/LDPlayer/BlueStacks files and props + build-string scoring | 2 |
| Simulator | iOS | `TARGET_OS_SIMULATOR`, `SIMULATOR_DEVICE_NAME` | 8 |
| Java debugger | Android | `Debug.isDebuggerConnected` / `waitingForDebugger` | 3 |
| Native debugger | Android | `TracerPid` in `/proc/self/status` | 9 |
| Debugger | iOS | `sysctl` `P_TRACED` + `PT_DENY_ATTACH` when enforcing | 1 |
| Hooking frameworks | Android | `/proc/self/maps` libs, Frida thread names, Frida ports 27042/27047, Xposed class/stack | 22 |
| Code injection | Android | `.so` mapped from `/data/local/tmp`, external storage, memfd, deleted files, other apps' data | 35 |
| Hooking frameworks | iOS | dyld image names (Frida, Substrate, libhooker, ElleKit, …), Frida ports | 5 |
| Injected libraries | iOS | dyld images outside bundle/system paths, `DYLD_INSERT_LIBRARIES` | 4 |
| Screenshot protection | Android | `FLAG_SECURE` (also covers recents, recording, casting) | – |
| Screenshot protection | iOS | content hosted in secure-text-entry canvas; screenshot notification reported | 3 |
| Screen recording | iOS | `UIScreen.isCaptured` → black shade | 6 |
| Screen mirroring | iOS / Android | external screens → shade / `FLAG_SECURE` | 41 |
| Untrusted keyboard | Android | default IME must be system or signer-trusted | 4 |
| Untrusted screen reader | Android | enabled accessibility services must be system or signer-trusted | 5 |
| Task hijacking | Android | `taskAffinity=""` on MainActivity (manifest) | – |
| Tapjacking | Android | `filterTouchesWhenObscured` + drop obscured `MotionEvent`s | 34 |
| Emulated input | Android | drop touches from virtual / id≤0 input devices | 31 |
| Private space / work profile | Android | `isManagedProfile`, `isProfile`, `isPrivateProfile` (reflected) | 32 |
| Virtual-space apps | Android | data-dir layout and uid consistency | 29 |
| Unlocked bootloader | Android | `verifiedbootstate`, `flash.locked`, `vbmeta.device_state` | 33 |
| VPN | Android | `TRANSPORT_VPN` + tun/ppp/wg interfaces | 37 |
| Developer mode | Android | `DEVELOPMENT_SETTINGS_ENABLED`, `ADB_ENABLED` | 40 |
| macOS (Apple silicon) | iOS | `NSProcessInfo.isiOSAppOnMac` | 7 |
| Native code hooks | Android | native: in-memory vs on-disk prologue of ~30 libc/libdl functions and the shield's own checks | 6 |
| Memory scanning | Android | native: inotify on `/proc/self/mem` | 42 |
| Repackaging (native) | Android | native: APK v2/v3/v3.1 signing block parsed from the mapped APK, built-in SHA-256 | 1 |
| Native code obfuscation | Android | ❌ not reproducible in a plugin | – |

## Gaps (honest assessment)

1. **Self-protection.** AppShield's runtime is obfuscated and checks its own integrity. On Android, the
   native layer checks its own function prologues, runs a watchdog independent of Java, and has a raw
   `exit_group` fail-safe, so patching only the Java enforcer no longer disables enforcement. The C
   library itself is not obfuscated, though, and a determined attacker can patch it statically and
   re-sign. That re-sign is what the signature checks catch, unless they are patched too. Server-side
   attestation (Play Integrity / App Attest) remains the real backstop. iOS has no equivalent layer yet.
2. **Timing.** AppShield blocks before any app code runs. This plugin loads with `onload=true`, so
   checks start as the WebView is created. On the test emulator, detection landed about 1 s after the
   first frame.
3. **Hiders.** Raw syscalls defeat libc-hooking hiders. Mount-namespace hiders (Shamiko, Zygisk
   DenyList) remove the artifacts outright, so they are still invisible to any in-app check, native or not.
4. **Memory scanners using `process_vm_readv`** do not trigger the `/proc/self/mem` watch. Non-root ones
   are blocked by `PR_SET_DUMPABLE 0`; root ones are not.
5. **Not implemented:** iOS developer-mode detection, native code obfuscation, native layer for iOS.

## Verification (Android, 2026-11-03)

Throwaway Cordova app (cordova-android 15.1.0, AGP 8.10.1, NDK 27.0.12077973) on an API 36 x86_64
emulator with Magisk:

| Test | Result |
|---|---|
| `libzshield.so` built for arm64-v8a, armeabi-v7a, x86, x86_64; only `JNI_OnLoad` exported | ✅ |
| Root: Java and native (raw `faccessat`, mountinfo) both detect Magisk | ✅ |
| Native APK signer SHA-256 == PackageManager == `apksigner` | ✅ |
| No false positives from hook / Frida / injection / tracer checks on a clean process | ✅ |
| `cat /proc/<pid>/mem` from another process → code 42 | ✅ |
| 1-byte `int3` patched into libc `inotify_add_watch` → code 6 on the next watchdog pass | ✅ |
| Enforcing: ExitOnURL opened in browser, process killed | ✅ |
| Arm64 device | not tested |

### Frida 17.25.2 (official android-x86_64 `frida-server` and `frida-inject`), same emulator

| Test | Result |
|---|---|
| `frida-server` listening, app resumed → code 22 `port:127.0.0.1:27042` (Java, on full scans: start/resume) | ✅ |
| `frida-inject` agent + `Interceptor.attach` on libc `open`/`fopen`/`access` → within one watchdog pass: code 9 (`native-TracerPid` during injection); code 22 (agent memfd in maps and fds, `gum-js-loop`/`gmain`/`gdbus`/`pool-spawner` threads, agent strings in memory); code 6 (`open`, `fopen`, `access`, plus `exit`/`_exit` that the agent patches itself) | ✅ |
| Enforcing release build, `PR_SET_DUMPABLE 0` applied (`/proc/<pid>/mem` owned by root) | ✅ |
| Fail-safe: injection detected while the injector held the main thread, so the Java enforcer never ran (no kill, no ExitOnURL). Process ended 3.05 s later with `exited cleanly (0)`, i.e. the native raw `exit_group` | ✅ |

Not exercised: the attacker script that turns libc `kill`/`exit`/`_exit` into no-ops never loaded,
because the injection itself was caught and the app died first. A renamed Frida build was not tried.
