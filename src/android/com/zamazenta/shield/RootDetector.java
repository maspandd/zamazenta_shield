package com.zamazenta.shield;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Privilege-escalation artifacts: su binaries, root managers, test-keys builds, tampered mounts. */
final class RootDetector {
    private static final String[] SU_PATHS = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/system/bin/.ext/.su", "/data/local/su", "/data/local/bin/su",
            "/data/local/xbin/su", "/cache/su", "/data/su", "/dev/su", "/system/xbin/daemonsu",
            "/system/app/Superuser.apk", "/system/etc/init.d/99SuperSUDaemon", "/sbin/.magisk",
            "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap", "/system/xbin/busybox",
    };

    /** Keep in sync with the {@code <queries>} block in plugin.xml (package visibility, API 30+). */
    private static final String[] ROOT_PACKAGES = {
            "com.topjohnwu.magisk", "io.github.vvb2060.magisk", "io.github.huskydg.magisk",
            "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.noshufou.android.su", "com.thirdparty.superuser",
            "com.kingroot.kinguser", "com.kingo.root", "com.zachspong.temprootremovejb",
            "com.devadvance.rootcloak", "com.devadvance.rootcloakplus", "de.robv.android.xposed.installer",
            "org.lsposed.manager", "com.saurik.substrate", "com.amphoras.hidemyroot",
    };

    private RootDetector() {}

    static void scan(Context context, ShieldConfig config, List<Detection> out) {
        List<String> evidence = new ArrayList<>();

        for (String path : SU_PATHS) {
            if (SystemFiles.exists(path)) evidence.add("file:" + path);
        }
        String pathEnv = System.getenv("PATH");
        if (pathEnv != null) {
            for (String dir : pathEnv.split(":")) {
                if (!dir.isEmpty() && SystemFiles.exists(new File(dir, "su").getPath())) evidence.add("path:" + dir + "/su");
            }
        }

        if (Build.TAGS != null && Build.TAGS.contains("test-keys")) evidence.add("build:test-keys");
        if ("0".equals(SystemFiles.prop("ro.secure"))) evidence.add("prop:ro.secure=0");
        if ("1".equals(SystemFiles.prop("ro.debuggable"))) evidence.add("prop:ro.debuggable=1");

        PackageManager pm = context.getPackageManager();
        for (String pkg : ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                evidence.add("package:" + pkg);
            } catch (PackageManager.NameNotFoundException ignored) {
                // Not installed, or hidden from us.
            }
        }

        for (String line : SystemFiles.lines("/proc/self/mounts")) {
            String lower = line.toLowerCase(Locale.US);
            if (lower.contains("magisk") || lower.contains("kernelsu") || lower.contains("/sbin/.core")) {
                evidence.add("mount:" + line.trim());
                continue;
            }
            String[] fields = line.split("\\s+");
            if (fields.length >= 4 && "/system".equals(fields[1]) && fields[3].startsWith("rw")) {
                evidence.add("mount:/system rw");
            }
        }

        if (config.blockHiddenSePolicyArtifacts && "0".equals(SystemFiles.firstLine("/sys/fs/selinux/enforce"))) {
            evidence.add("selinux:permissive");
        }

        Detection.addIfAny(out, Threat.ROOTED, evidence);
    }
}
