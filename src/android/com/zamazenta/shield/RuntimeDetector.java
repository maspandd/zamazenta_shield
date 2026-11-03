package com.zamazenta.shield;

import android.content.Context;
import android.os.Debug;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** In-process threats: attached debuggers, hooking frameworks and foreign native code. */
final class RuntimeDetector {
    private static final String[] HOOK_LIBRARY_MARKERS = {
            "frida", "libgadget", "linjector", "libsubstrate", "xposed", "lspd", "lsplant", "edxp",
            "riru", "zygisk", "/data/adb/", "libsandhook", "libepic", "libwhale", "libpine", "libdobby",
    };
    private static final String[] HOOK_THREAD_NAMES = {
            "gum-js-loop", "gmain", "gdbus", "pool-frida", "linjector", "frida",
    };
    private static final String[] HOOK_STACK_MARKERS = {
            "de.robv.android.xposed", "com.saurik.substrate", "lsposed", "edxposed",
    };
    private static final int[] FRIDA_PORTS = {27042, 27047};
    private static final int PORT_TIMEOUT_MS = 100;

    private RuntimeDetector() {}

    static void scanDebuggers(List<Detection> out) {
        List<String> java = new ArrayList<>();
        if (Debug.isDebuggerConnected()) java.add("jdwp:connected");
        if (Debug.waitingForDebugger()) java.add("jdwp:waiting");
        Detection.addIfAny(out, Threat.JAVA_DEBUGGER, java);

        String tracer = SystemFiles.statusField("TracerPid");
        if (tracer != null && !"0".equals(tracer)) out.add(Detection.of(Threat.NATIVE_DEBUGGER, "TracerPid:" + tracer));
    }

    static void scanHooks(Context context, List<Detection> out) {
        List<String> hooks = new ArrayList<>();
        List<String> injected = new ArrayList<>();
        String ownPackage = context.getPackageName();

        for (String line : SystemFiles.lines("/proc/self/maps")) {
            String path = SystemFiles.mapsPath(line);
            if (path.isEmpty()) continue;
            String lower = path.toLowerCase(Locale.US);
            if (containsAny(lower, HOOK_LIBRARY_MARKERS)) {
                hooks.add("maps:" + path);
            } else if (isForeignLibrary(lower, ownPackage)) {
                injected.add("maps:" + path);
            }
        }

        File[] tasks = new File("/proc/self/task").listFiles();
        if (tasks != null) {
            for (File task : tasks) {
                String name = SystemFiles.firstLine(new File(task, "comm").getPath());
                if (name != null && containsAny(name.toLowerCase(Locale.US), HOOK_THREAD_NAMES)) hooks.add("thread:" + name);
            }
        }

        for (int port : FRIDA_PORTS) {
            if (localPortOpen(port)) hooks.add("port:127.0.0.1:" + port);
        }

        try {
            ClassLoader.getSystemClassLoader().loadClass("de.robv.android.xposed.XposedBridge");
            hooks.add("class:de.robv.android.xposed.XposedBridge");
        } catch (ClassNotFoundException ignored) {
            // Expected on a clean device.
        }
        for (StackTraceElement frame : new Throwable().getStackTrace()) {
            String cls = frame.getClassName().toLowerCase(Locale.US);
            if (containsAny(cls, HOOK_STACK_MARKERS)) hooks.add("stack:" + frame.getClassName());
        }

        Detection.addIfAny(out, Threat.HOOKING_FRAMEWORK, hooks);
        Detection.addIfAny(out, Threat.CODE_INJECTION, injected);
    }

    /** Native code mapped from locations an APK install never produces. */
    private static boolean isForeignLibrary(String path, String ownPackage) {
        if (!path.contains(".so")) return false;
        if (path.startsWith("/data/local/tmp") || path.startsWith("/sdcard") || path.startsWith("/storage")
                || path.startsWith("/memfd:") || path.endsWith("(deleted)")) {
            return true;
        }
        boolean appData = path.startsWith("/data/data/") || path.startsWith("/data/user/");
        return appData && !path.contains("/" + ownPackage.toLowerCase(Locale.US) + "/");
    }

    private static boolean localPortOpen(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), PORT_TIMEOUT_MS);
            return true;
        } catch (IOException | SecurityException e) {
            return false;
        }
    }

    private static boolean containsAny(String value, String[] markers) {
        for (String marker : markers) {
            if (value.contains(marker)) return true;
        }
        return false;
    }
}
