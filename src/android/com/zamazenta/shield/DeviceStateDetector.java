package com.zamazenta.shield;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.UserManager;
import android.provider.Settings;
import android.view.accessibility.AccessibilityManager;

import java.lang.reflect.Method;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Device configuration and the environment the app was launched into. */
final class DeviceStateDetector {
    private static final String[] VPN_INTERFACE_PREFIXES = {"tun", "ppp", "pptp", "ipsec", "wg"};

    private DeviceStateDetector() {}

    static void scanDeveloperMode(Context context, List<Detection> out) {
        ContentResolver resolver = context.getContentResolver();
        List<String> evidence = new ArrayList<>();
        if (Settings.Global.getInt(resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1) {
            evidence.add("settings:development_settings_enabled");
        }
        if (Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) == 1) evidence.add("settings:adb_enabled");
        Detection.addIfAny(out, Threat.DEVELOPER_MODE, evidence);
    }

    static void scanBootloader(List<Detection> out) {
        List<String> evidence = new ArrayList<>();
        if ("orange".equals(SystemFiles.prop("ro.boot.verifiedbootstate"))) evidence.add("prop:verifiedbootstate=orange");
        if ("0".equals(SystemFiles.prop("ro.boot.flash.locked"))) evidence.add("prop:flash.locked=0");
        if ("unlocked".equals(SystemFiles.prop("ro.boot.vbmeta.device_state"))) evidence.add("prop:vbmeta.device_state=unlocked");
        Detection.addIfAny(out, Threat.UNLOCKED_BOOTLOADER, evidence);
    }

    static void scanVpn(Context context, List<Detection> out) {
        List<String> evidence = new ArrayList<>();
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network network = cm == null ? null : cm.getActiveNetwork();
            NetworkCapabilities caps = network == null ? null : cm.getNetworkCapabilities(network);
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) evidence.add("transport:vpn");
        } catch (SecurityException ignored) {
            // ACCESS_NETWORK_STATE missing; fall through to the interface scan.
        }
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface ni : interfaces) {
                String name = ni.getName().toLowerCase(Locale.US);
                if (!ni.isUp()) continue;
                for (String prefix : VPN_INTERFACE_PREFIXES) {
                    if (name.startsWith(prefix)) evidence.add("iface:" + ni.getName());
                }
            }
        } catch (SocketException | NullPointerException ignored) {
            // No interfaces enumerable.
        }
        Detection.addIfAny(out, Threat.VPN, evidence);
    }

    static void scanProfile(Context context, List<Detection> out) {
        List<String> evidence = new ArrayList<>();
        UserManager um = (UserManager) context.getSystemService(Context.USER_SERVICE);
        if (um != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                if (um.isManagedProfile()) evidence.add("profile:managed");
                if (um.isProfile()) evidence.add("profile:non-primary");
            }
            // UserManager#isPrivateProfile is Android 15+; reflected so older compileSdk levels still build.
            if (invokeBoolean(um, "isPrivateProfile")) evidence.add("profile:private");
        }
        Detection.addIfAny(out, Threat.PRIVATE_SPACE, evidence);
    }

    /** Virtual-space / app-cloner hosts relocate the data directory or run us under their uid. */
    static void scanVirtualSpace(Context context, List<Detection> out) {
        List<String> evidence = new ArrayList<>();
        ApplicationInfo info = context.getApplicationInfo();
        String pkg = Pattern.quote(context.getPackageName());
        Pattern expected = Pattern.compile("^(/data|/mnt/expand/[^/]+)/(data|user/\\d+)/" + pkg + "/?$");
        if (info.dataDir != null && !expected.matcher(info.dataDir).matches()) evidence.add("dataDir:" + info.dataDir);
        int myUid = android.os.Process.myUid();
        if (info.uid != myUid) evidence.add("uid:" + myUid + "!=" + info.uid);
        Detection.addIfAny(out, Threat.VIRTUAL_SPACE, evidence);
    }

    static void scanKeyboard(Context context, ShieldConfig config, List<Detection> out) {
        String ime = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
        if (ime == null || ime.isEmpty()) return;
        String pkg = ime.split("/")[0];
        if (!isTrusted(context, pkg, config.trustedKeyboardSigners)) {
            out.add(Detection.of(Threat.UNTRUSTED_KEYBOARD, "ime:" + ime));
        }
    }

    static void scanScreenReaders(Context context, ShieldConfig config, List<Detection> out) {
        AccessibilityManager am = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
        if (am == null || !am.isEnabled()) return;
        List<String> evidence = new ArrayList<>();
        for (AccessibilityServiceInfo info : am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)) {
            ServiceInfo service = info.getResolveInfo() == null ? null : info.getResolveInfo().serviceInfo;
            if (service == null) continue;
            if (!isTrusted(context, service.packageName, config.trustedScreenReaderSigners)) {
                evidence.add("a11y:" + service.packageName + "/" + service.name);
            }
        }
        Detection.addIfAny(out, Threat.UNTRUSTED_SCREEN_READER, evidence);
    }

    /** Pre-installed (system or updated-system) packages are trusted; others must match a configured signer. */
    private static boolean isTrusted(Context context, String pkg, Set<String> trustedSigners) {
        PackageManager pm = context.getPackageManager();
        try {
            ApplicationInfo info = pm.getApplicationInfo(pkg, 0);
            if ((info.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0) return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
        return Signers.anyMatch(Signers.fingerprints(pm, pkg), trustedSigners);
    }

    private static boolean invokeBoolean(Object target, String methodName) {
        try {
            Method method = target.getClass().getMethod(methodName);
            Object result = method.invoke(target);
            return Boolean.TRUE.equals(result);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return false;
        }
    }
}
