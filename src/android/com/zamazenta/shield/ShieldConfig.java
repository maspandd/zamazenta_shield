package com.zamazenta.shield;

import org.apache.cordova.CordovaPreferences;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Set;

/**
 * Runtime policy read from config.xml preferences. Preference names and defaults follow the
 * OutSystems AppShield extensibility keys, so an existing AppShield "preferences" block can be
 * reused unchanged.
 */
final class ShieldConfig {
    final boolean disabled;
    final boolean debugMode;
    final boolean reportOnly;
    final long recheckIntervalMs;

    final boolean allowRooted;
    final boolean allowScreenshot;
    final boolean allowPrivateSpace;
    final boolean allowTapjacking;

    final boolean blockDeveloperMode;
    final boolean blockEmulator;
    final boolean blockUntrustedKeyboards;
    final boolean blockUntrustedScreenReaders;
    final boolean blockUnlockedBootloader;
    final boolean blockNonSystemOverlays;
    final boolean blockEmulatedInput;
    final boolean blockScreenMirroring;
    final boolean blockVpn;
    final boolean blockHiddenSePolicyArtifacts;
    final boolean blockMemoryScan;
    final boolean blockCodeTraceDetection;
    final boolean nativeBuild;
    final boolean requireNative;

    final String exitOnUrl;
    final Set<String> signerFingerprints;
    final Set<String> trustedKeyboardSigners;
    final Set<String> trustedScreenReaderSigners;

    ShieldConfig(CordovaPreferences p) {
        disabled = p.getBoolean("DisableAppShielding", false);
        debugMode = p.getBoolean("AppShieldDebugMode", false);
        reportOnly = p.getBoolean("ZamazentaShieldReportOnly", false);
        recheckIntervalMs = parseLong(p.getString("ZamazentaShieldRecheckIntervalMs", "5000"), 5000L);

        allowRooted = p.getBoolean("AllowJailbrokenRootedDevices", false);
        allowScreenshot = p.getBoolean("AllowScreenshot", false);
        allowPrivateSpace = p.getBoolean("AllowPrivateSpace", true);
        allowTapjacking = p.getBoolean("AllowTapjacking", true);

        blockDeveloperMode = p.getBoolean("BlockDeveloperMode", false);
        blockEmulator = p.getBoolean("BlockEmulator", true);
        blockUntrustedKeyboards = p.getBoolean("BlockUntrustedKeyboards", false);
        blockUntrustedScreenReaders = p.getBoolean("BlockUntrustedScreenreaders", false);
        blockUnlockedBootloader = p.getBoolean("BlockUnlockedBootloader", true);
        blockNonSystemOverlays = p.getBoolean("BlockNonSystemOverlays", true);
        blockEmulatedInput = p.getBoolean("BlockEmulatedInput", false);
        blockScreenMirroring = p.getBoolean("BlockScreenMirroring", false);
        blockVpn = p.getBoolean("BlockVPN", false);
        blockHiddenSePolicyArtifacts = p.getBoolean("BlockHiddenSEPolicyArtifacts", false);
        blockMemoryScan = p.getBoolean("BlockMemoryScan", true);
        blockCodeTraceDetection = p.getBoolean("BlockCodeTraceDetection", true);
        nativeBuild = p.getBoolean("ZamazentaShieldNativeBuild", true);
        // A build made with ZamazentaShieldNativeBuild=false ships without libzshield by design.
        requireNative = nativeBuild && p.getBoolean("ZamazentaShieldRequireNative", true);

        exitOnUrl = p.getString("ExitOnURL", "").trim();
        signerFingerprints = Signers.parseList(p.getString("ApplicationSignerCertificate", ""));
        trustedKeyboardSigners = Signers.parseList(p.getString("AddTrustedKeyboardSigner", ""));
        trustedScreenReaderSigners = Signers.parseList(p.getString("AddTrustedScreenReaderSigner", ""));
    }

    boolean enforcing() {
        return !disabled && !debugMode && !reportOnly;
    }

    /** Which native checks run, derived from the same policy as the Java checks. */
    int nativeFlags() {
        int flags = NativeShield.CHECK_HOOKS;
        if (!allowRooted) flags |= NativeShield.CHECK_ROOT;
        if (!debugMode && blockCodeTraceDetection) flags |= NativeShield.CHECK_TRACER;
        if (!signerFingerprints.isEmpty()) flags |= NativeShield.CHECK_SIGNATURE;
        if (blockMemoryScan) flags |= NativeShield.WATCH_MEMORY;
        if (enforcing() && blockCodeTraceDetection) flags |= NativeShield.HARDEN_PTRACE;
        if (enforcing()) flags |= NativeShield.ENFORCE;
        return flags;
    }

    private static long parseLong(String value, long fallback) {
        try {
            return Math.max(0L, Long.parseLong(value.trim()));
        } catch (NumberFormatException | NullPointerException e) {
            return fallback;
        }
    }

    JSONObject toJson() {
        JSONObject json = new JSONObject();
        try {
            json.put("DisableAppShielding", disabled);
            json.put("AppShieldDebugMode", debugMode);
            json.put("ZamazentaShieldReportOnly", reportOnly);
            json.put("ZamazentaShieldRecheckIntervalMs", recheckIntervalMs);
            json.put("AllowJailbrokenRootedDevices", allowRooted);
            json.put("AllowScreenshot", allowScreenshot);
            json.put("AllowPrivateSpace", allowPrivateSpace);
            json.put("AllowTapjacking", allowTapjacking);
            json.put("BlockDeveloperMode", blockDeveloperMode);
            json.put("BlockEmulator", blockEmulator);
            json.put("BlockUntrustedKeyboards", blockUntrustedKeyboards);
            json.put("BlockUntrustedScreenreaders", blockUntrustedScreenReaders);
            json.put("BlockUnlockedBootloader", blockUnlockedBootloader);
            json.put("BlockNonSystemOverlays", blockNonSystemOverlays);
            json.put("BlockEmulatedInput", blockEmulatedInput);
            json.put("BlockScreenMirroring", blockScreenMirroring);
            json.put("BlockVPN", blockVpn);
            json.put("BlockHiddenSEPolicyArtifacts", blockHiddenSePolicyArtifacts);
            json.put("BlockMemoryScan", blockMemoryScan);
            json.put("BlockCodeTraceDetection", blockCodeTraceDetection);
            json.put("ZamazentaShieldNativeBuild", nativeBuild);
            json.put("ZamazentaShieldRequireNative", requireNative);
            json.put("ExitOnURL", exitOnUrl);
            json.put("ApplicationSignerCertificateCount", signerFingerprints.size());
        } catch (JSONException ignored) {
            // Only non-finite doubles make put() throw.
        }
        return json;
    }
}
