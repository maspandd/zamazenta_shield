package com.zamazenta.shield;

import android.util.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Bridge to libzshield. The native layer repeats the most attacked checks with raw syscalls
 * (immune to libc hooks), adds inline-hook, memory-scanner and APK-signature checks that cannot be
 * done from Java, and runs its own watchdog thread plus a fail-safe exit that survives the Java
 * side being patched out.
 */
final class NativeShield {
    interface Listener {
        void onDetections(List<Detection> detections);
    }

    // Must match zs_jni.c.
    static final int CHECK_ROOT = 1;
    static final int CHECK_TRACER = 1 << 1;
    static final int CHECK_HOOKS = 1 << 2;
    static final int CHECK_SIGNATURE = 1 << 3;
    static final int WATCH_MEMORY = 1 << 4;
    static final int HARDEN_PTRACE = 1 << 5;
    static final int ENFORCE = 1 << 6;

    private static final String TAG = "ZamazentaShield";
    private static volatile Listener listener;
    private static boolean loaded;

    private NativeShield() {}

    static synchronized boolean load() {
        if (loaded) return true;
        try {
            System.loadLibrary("zshield");
            loaded = true;
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, "libzshield unavailable: " + e.getMessage());
        }
        return loaded;
    }

    static boolean start(int flags, int intervalMs, int sdkInt, String packageName, String apkPath,
                         Set<String> signerFingerprints, Listener detectionListener) {
        listener = detectionListener;
        return nativeStart(flags, intervalMs, sdkInt, packageName, apkPath, signerFingerprints.toArray(new String[0]));
    }

    static List<Detection> scan(int flags) {
        return parse(nativeScan(flags));
    }

    /** Called by native threads (watchdog, memory watcher). */
    @SuppressWarnings("unused")
    static void onNativeDetections(String[] items) {
        Listener current = listener;
        if (current == null) return;
        List<Detection> detections = parse(items);
        if (!detections.isEmpty()) current.onDetections(detections);
    }

    /** Items are "code|evidence"; evidence for the same code is grouped into one Detection. */
    private static List<Detection> parse(String[] items) {
        List<Detection> out = new ArrayList<>();
        if (items == null) return out;
        for (String item : items) {
            if (item == null) continue;
            int separator = item.indexOf('|');
            if (separator <= 0) continue;
            Threat threat;
            try {
                threat = Threat.fromCode(Integer.parseInt(item.substring(0, separator)));
            } catch (NumberFormatException e) {
                continue;
            }
            if (threat != null) out.add(Detection.of(threat, item.substring(separator + 1)));
        }
        return Detection.merge(out);
    }

    private static native boolean nativeStart(int flags, int intervalMs, int sdkInt, String packageName,
                                              String apkPath, String[] signerFingerprints);

    private static native String[] nativeScan(int flags);
}
