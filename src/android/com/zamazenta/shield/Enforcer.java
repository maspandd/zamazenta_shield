package com.zamazenta.shield;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.util.Log;

import org.json.JSONObject;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Decides what happens to each detection and carries it out:
 * <ul>
 *   <li>{@code exit} – open ExitOnURL (if set) and terminate the process, as AppShield does;</li>
 *   <li>{@code reported} – AppShieldDebugMode / ZamazentaShieldReportOnly: emit the event only;</li>
 *   <li>{@code mitigated} – already neutralised in place (input dropped, display blanked).</li>
 * </ul>
 */
final class Enforcer {
    interface Sink {
        void emit(JSONObject event);
    }

    static final String ACTION_EXIT = "exit";
    static final String ACTION_REPORTED = "reported";
    static final String ACTION_MITIGATED = "mitigated";

    private static final String TAG = "ZamazentaShield";
    private static final long EXIT_DELAY_MS = 300;
    private static final long MITIGATION_REPORT_INTERVAL_MS = 5000;

    private final Activity activity;
    private final ShieldConfig config;
    private final Sink sink;
    private final Runnable blankScreen;
    private final AtomicBoolean terminating = new AtomicBoolean();
    private final Set<String> reported = Collections.synchronizedSet(new HashSet<>());
    private final Map<Threat, Long> lastMitigation = new ConcurrentHashMap<>();

    Enforcer(Activity activity, ShieldConfig config, Sink sink, Runnable blankScreen) {
        this.activity = activity;
        this.config = config;
        this.sink = sink;
        this.blankScreen = blankScreen;
    }

    String actionFor(Threat threat) {
        if (threat.mitigatedInPlace) return ACTION_MITIGATED;
        return config.debugMode || config.reportOnly ? ACTION_REPORTED : ACTION_EXIT;
    }

    void handle(List<Detection> detections) {
        for (Detection detection : detections) handle(detection);
    }

    void handle(Detection detection) {
        String action = actionFor(detection.threat);
        if (!shouldEmit(detection, action)) return;
        Log.w(TAG, detection.threat.description + " [" + detection.threat.code + "] -> " + action + " " + detection.evidence);
        sink.emit(detection.toJson(action));
        if (ACTION_EXIT.equals(action)) terminate(detection.threat);
    }

    private boolean shouldEmit(Detection detection, String action) {
        switch (action) {
            case ACTION_EXIT:
                return terminating.compareAndSet(false, true);
            case ACTION_MITIGATED: {
                long now = System.currentTimeMillis();
                Long last = lastMitigation.get(detection.threat);
                if (last != null && now - last < MITIGATION_REPORT_INTERVAL_MS) return false;
                lastMitigation.put(detection.threat, now);
                return true;
            }
            default:
                return reported.add(detection.threat.id + detection.evidence);
        }
    }

    private void terminate(Threat threat) {
        activity.runOnUiThread(() -> {
            blankScreen.run();
            Uri exitUri = exitUri(threat);
            if (exitUri != null) {
                try {
                    activity.startActivity(new Intent(Intent.ACTION_VIEW, exitUri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
                } catch (ActivityNotFoundException e) {
                    Log.w(TAG, "No browser available for ExitOnURL");
                }
            }
            activity.finishAndRemoveTask();
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                Process.killProcess(Process.myPid());
                System.exit(0);
            }, EXIT_DELAY_MS);
        });
    }

    /** Same parameters AppShield appends: reason, manufacturer, model, ANDROID (API level). */
    private Uri exitUri(Threat threat) {
        if (config.exitOnUrl.isEmpty()) return null;
        Uri base = Uri.parse(config.exitOnUrl);
        String scheme = base.getScheme();
        if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
            Log.w(TAG, "ExitOnURL ignored: only http(s) URLs are opened");
            return null;
        }
        return base.buildUpon()
                .appendQueryParameter("reason", String.valueOf(threat.code))
                .appendQueryParameter("manufacturer", Build.MANUFACTURER)
                .appendQueryParameter("model", Build.MODEL)
                .appendQueryParameter("ANDROID", String.valueOf(Build.VERSION.SDK_INT))
                .build();
    }
}
