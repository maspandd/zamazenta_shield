package com.zamazenta.shield;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Repackaging: the running APK must be signed by one of the configured certificates. */
final class IntegrityDetector {
    private static final String TAG = "ZamazentaShield";
    private static boolean warnedUnconfigured;

    private IntegrityDetector() {}

    static void scan(Context context, ShieldConfig config, List<Detection> out) {
        List<String> evidence = new ArrayList<>();

        if (config.signerFingerprints.isEmpty()) {
            if (!warnedUnconfigured) {
                warnedUnconfigured = true;
                Log.w(TAG, "ApplicationSignerCertificate not set; signature check skipped. "
                        + "Repackaging protection is incomplete until it is configured.");
            }
        } else {
            Set<String> actual = Signers.fingerprints(context.getPackageManager(), context.getPackageName());
            if (actual.isEmpty()) {
                evidence.add("signer:unreadable");
            } else if (!Signers.anyMatch(actual, config.signerFingerprints)) {
                for (String fingerprint : actual) evidence.add("signer:" + fingerprint);
            }
        }

        // A release build re-signed with android:debuggable="true" is the classic repackaging move.
        if (!config.debugMode && (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            evidence.add("manifest:debuggable");
        }

        Detection.addIfAny(out, Threat.REPACKAGED, evidence);
    }
}
