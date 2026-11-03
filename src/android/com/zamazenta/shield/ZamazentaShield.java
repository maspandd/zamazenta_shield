package com.zamazenta.shield;

import android.app.Activity;
import android.content.Context;
import android.os.Build;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Cordova entry point. Loaded at startup (onload=true): installs the window guards, runs a full
 * scan, then re-runs the cheap runtime checks (debugger, hooks, VPN) on a fixed interval.
 */
public class ZamazentaShield extends CordovaPlugin {
    private static final String TAG = "ZamazentaShield";
    private static final String VERSION = "0.1.0";
    private static final int MAX_PENDING_EVENTS = 50;
    /** Synchronous native checks; the memory watcher and ptrace hardening are started once by start(). */
    private static final int NATIVE_SCAN_FLAGS = NativeShield.CHECK_ROOT | NativeShield.CHECK_TRACER
            | NativeShield.CHECK_HOOKS | NativeShield.CHECK_SIGNATURE | NativeShield.ENFORCE;

    private ShieldConfig config;
    private boolean nativeLoaded;
    private Enforcer enforcer;
    private ScreenGuard screenGuard;
    private ScheduledExecutorService executor;

    private final Object eventLock = new Object();
    private CallbackContext watcher;
    private final List<JSONObject> pendingEvents = new ArrayList<>();
    private volatile List<JSONObject> lastScan = Collections.emptyList();

    @Override
    protected void pluginInitialize() {
        config = new ShieldConfig(preferences);
        if (config.disabled) {
            Log.i(TAG, "DisableAppShielding=true; protections are off");
            return;
        }
        Activity activity = cordova.getActivity();
        screenGuard = new ScreenGuard(activity, config, detection -> enforcer.handle(detection));
        enforcer = new Enforcer(activity, config, this::emit, screenGuard::blank);
        activity.runOnUiThread(screenGuard::install);

        nativeLoaded = NativeShield.load();
        if (nativeLoaded) {
            Context app = activity.getApplicationContext();
            NativeShield.start(config.nativeFlags(), (int) Math.min(config.recheckIntervalMs, Integer.MAX_VALUE),
                    Build.VERSION.SDK_INT, app.getPackageName(), app.getApplicationInfo().sourceDir,
                    config.signerFingerprints, detections -> enforcer.handle(detections));
        }

        executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "zshield-scan");
            thread.setDaemon(true);
            return thread;
        });
        executor.execute(() -> enforcer.handle(scan(true)));
        if (config.recheckIntervalMs > 0) {
            executor.scheduleWithFixedDelay(() -> enforcer.handle(scan(false)),
                    config.recheckIntervalMs, config.recheckIntervalMs, TimeUnit.MILLISECONDS);
        }
    }

    @Override
    public void onResume(boolean multitasking) {
        submit(() -> enforcer.handle(scan(true)));
    }

    @Override
    public void onDestroy() {
        if (executor != null) executor.shutdownNow();
        if (screenGuard != null) cordova.getActivity().runOnUiThread(screenGuard::uninstall);
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        switch (action) {
            case "getStatus":
                callbackContext.success(status());
                return true;
            case "check":
                if (config.disabled) {
                    callbackContext.success(new JSONArray());
                    return true;
                }
                if (!submit(() -> {
                    List<Detection> detections = scan(true);
                    enforcer.handle(detections);
                    callbackContext.success(new JSONArray(lastScan));
                })) {
                    callbackContext.error("Scanner stopped");
                }
                return true;
            case "watch":
                watch(callbackContext);
                return true;
            default:
                return false;
        }
    }

    /** Full scans include the slower filesystem / package checks; periodic scans only the volatile ones. */
    private List<Detection> scan(boolean full) {
        Context context = cordova.getActivity().getApplicationContext();
        List<Detection> out = new ArrayList<>();
        try {
            if (!config.debugMode) RuntimeDetector.scanDebuggers(out);
            RuntimeDetector.scanHooks(context, out);
            if (config.blockVpn) DeviceStateDetector.scanVpn(context, out);
            if (full) {
                if (!config.allowRooted) RootDetector.scan(context, config, out);
                IntegrityDetector.scan(context, config, out);
                if (config.blockEmulator) EmulatorDetector.scan(out);
                if (config.blockUnlockedBootloader) DeviceStateDetector.scanBootloader(out);
                if (config.blockDeveloperMode) DeviceStateDetector.scanDeveloperMode(context, out);
                if (!config.allowPrivateSpace) DeviceStateDetector.scanProfile(context, out);
                if (config.blockUntrustedKeyboards) DeviceStateDetector.scanKeyboard(context, config, out);
                if (config.blockUntrustedScreenReaders) DeviceStateDetector.scanScreenReaders(context, config, out);
                DeviceStateDetector.scanVirtualSpace(context, out);
                if (nativeLoaded) {
                    out.addAll(NativeShield.scan(config.nativeFlags() & NATIVE_SCAN_FLAGS));
                } else if (config.requireNative) {
                    // The build always ships libzshield; its absence means the APK was rebuilt without it.
                    out.add(Detection.of(Threat.REPACKAGED, "native:libzshield missing"));
                }
            }
        } catch (RuntimeException e) {
            // A failing heuristic must never take the app down on its own.
            Log.e(TAG, "Scan failed", e);
        }
        out = Detection.merge(out);
        if (full) {
            List<JSONObject> snapshot = new ArrayList<>();
            for (Detection d : out) snapshot.add(d.toJson(enforcer.actionFor(d.threat)));
            lastScan = Collections.unmodifiableList(snapshot);
        }
        return out;
    }

    private boolean submit(Runnable task) {
        if (executor == null) return false;
        try {
            executor.execute(task);
            return true;
        } catch (RejectedExecutionException e) {
            return false;
        }
    }

    private void watch(CallbackContext callbackContext) {
        List<JSONObject> backlog;
        synchronized (eventLock) {
            watcher = callbackContext;
            backlog = new ArrayList<>(pendingEvents);
            pendingEvents.clear();
        }
        PluginResult noResult = new PluginResult(PluginResult.Status.NO_RESULT);
        noResult.setKeepCallback(true);
        callbackContext.sendPluginResult(noResult);
        for (JSONObject event : backlog) send(callbackContext, event);
    }

    private void emit(JSONObject event) {
        CallbackContext target;
        synchronized (eventLock) {
            target = watcher;
            if (target == null) {
                if (pendingEvents.size() < MAX_PENDING_EVENTS) pendingEvents.add(event);
                return;
            }
        }
        send(target, event);
    }

    private static void send(CallbackContext target, JSONObject event) {
        PluginResult result = new PluginResult(PluginResult.Status.OK, event);
        result.setKeepCallback(true);
        target.sendPluginResult(result);
    }

    private JSONObject status() throws JSONException {
        JSONObject json = new JSONObject();
        json.put("platform", "android");
        json.put("version", VERSION);
        json.put("enabled", !config.disabled);
        json.put("enforcing", config.enforcing());
        json.put("native", nativeLoaded);
        json.put("detections", new JSONArray(lastScan));
        json.put("config", config.toJson());
        return json;
    }
}
