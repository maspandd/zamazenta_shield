package com.zamazenta.shield;

import android.os.Build;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Emulator heuristics. Any strong indicator triggers on its own; weak build-string indicators
 * need at least two matches, because some cheap real devices ship generic-looking build strings.
 */
final class EmulatorDetector {
    private static final String[] STRONG_FILES = {
            "/dev/qemu_pipe", "/dev/socket/qemud", "/dev/goldfish_pipe", "/system/bin/qemu-props",
            "/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace", "/dev/socket/genyd",
            "/dev/socket/baseband_genyd", "/fstab.nox", "/init.nox.rc", "/system/bin/nox-prop",
            "/system/bin/ldinit", "/system/lib/libldutils.so", "/data/.bluestacks.prop",
            "/system/priv-app/com.bluestacks.bstfolder.apk",
    };
    private static final String[] STRONG_HARDWARE = {"goldfish", "ranchu", "vbox86", "nox", "ttvm_x86"};

    private EmulatorDetector() {}

    static void scan(List<Detection> out) {
        List<String> strong = new ArrayList<>();
        List<String> weak = new ArrayList<>();

        for (String path : STRONG_FILES) {
            if (SystemFiles.exists(path)) strong.add("file:" + path);
        }
        String hardware = lower(Build.HARDWARE);
        for (String hw : STRONG_HARDWARE) {
            if (hardware.contains(hw)) strong.add("hardware:" + Build.HARDWARE);
        }
        if ("1".equals(SystemFiles.prop("ro.kernel.qemu")) || "1".equals(SystemFiles.prop("ro.boot.qemu"))) {
            strong.add("prop:qemu=1");
        }
        if (!SystemFiles.prop("ro.hardware.virtual_device").isEmpty()) strong.add("prop:ro.hardware.virtual_device");
        if (lower(Build.MANUFACTURER).contains("genymotion")) strong.add("manufacturer:" + Build.MANUFACTURER);

        String fingerprint = lower(Build.FINGERPRINT);
        String model = lower(Build.MODEL);
        String product = lower(Build.PRODUCT);
        if (fingerprint.startsWith("generic") || fingerprint.startsWith("unknown") || fingerprint.contains("emulator")) {
            weak.add("fingerprint:" + Build.FINGERPRINT);
        }
        if (model.contains("google_sdk") || model.contains("emulator") || model.contains("android sdk built for")
                || model.contains("sdk_gphone")) {
            weak.add("model:" + Build.MODEL);
        }
        if (product.contains("sdk") || product.contains("emulator") || product.contains("simulator")
                || product.contains("vbox86p")) {
            weak.add("product:" + Build.PRODUCT);
        }
        if (lower(Build.BRAND).startsWith("generic") && lower(Build.DEVICE).startsWith("generic")) {
            weak.add("brand/device:generic");
        }

        if (!strong.isEmpty() || weak.size() >= 2) {
            strong.addAll(weak);
            out.add(new Detection(Threat.EMULATOR, strong));
        }
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.US);
    }
}
