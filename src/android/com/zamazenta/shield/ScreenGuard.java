package com.zamazenta.shield;

import android.app.Activity;
import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.view.Display;
import android.view.InputDevice;
import android.view.MotionEvent;
import android.view.Window;
import android.view.WindowManager;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Window-level protections: screenshot/recording blocking (FLAG_SECURE), overlay hiding,
 * tapjacking and emulated-input filtering, and secondary-display blanking.
 * All methods must be called on the UI thread.
 */
final class ScreenGuard implements DisplayManager.DisplayListener {
    interface Reporter {
        void report(Detection detection);
    }

    private final Activity activity;
    private final ShieldConfig config;
    private final Reporter reporter;
    private DisplayManager displayManager;
    private Window.Callback originalCallback;
    private boolean mirroring;

    ScreenGuard(Activity activity, ShieldConfig config, Reporter reporter) {
        this.activity = activity;
        this.config = config;
        this.reporter = reporter;
    }

    void install() {
        Window window = activity.getWindow();
        if (!config.allowScreenshot) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        if (config.blockNonSystemOverlays && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.setHideOverlayWindows(true);
        }
        if (!config.allowTapjacking) window.getDecorView().setFilterTouchesWhenObscured(true);
        if (!config.allowTapjacking || config.blockEmulatedInput) wrapWindowCallback(window);
        if (config.blockScreenMirroring) {
            displayManager = (DisplayManager) activity.getSystemService(Context.DISPLAY_SERVICE);
            if (displayManager != null) {
                displayManager.registerDisplayListener(this, new Handler(Looper.getMainLooper()));
                refreshMirroring();
            }
        }
    }

    void uninstall() {
        if (displayManager != null) displayManager.unregisterDisplayListener(this);
        if (originalCallback != null) activity.getWindow().setCallback(originalCallback);
        originalCallback = null;
    }

    /** Hides all content immediately; used right before the app is terminated. */
    void blank() {
        activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        activity.getWindow().getDecorView().setAlpha(0f);
    }

    /** Intercepts touches before they reach the view tree, via a dynamic proxy of the activity's Window.Callback. */
    private void wrapWindowCallback(Window window) {
        final Window.Callback target = window.getCallback();
        if (target == null) return;
        originalCallback = target;
        Window.Callback proxy = (Window.Callback) Proxy.newProxyInstance(
                Window.Callback.class.getClassLoader(),
                new Class<?>[]{Window.Callback.class},
                (self, method, args) -> {
                    if ("dispatchTouchEvent".equals(method.getName()) && args != null && args.length == 1
                            && args[0] instanceof MotionEvent && shouldDrop((MotionEvent) args[0])) {
                        return true;
                    }
                    try {
                        return method.invoke(target, args);
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
        window.setCallback(proxy);
    }

    private boolean shouldDrop(MotionEvent event) {
        if (!config.allowTapjacking) {
            int obscured = MotionEvent.FLAG_WINDOW_IS_OBSCURED;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) obscured |= MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED;
            if ((event.getFlags() & obscured) != 0) {
                reporter.report(Detection.of(Threat.TAPJACKING,
                        String.format(Locale.US, "motionFlags:0x%x", event.getFlags())));
                return true;
            }
        }
        if (config.blockEmulatedInput && event.getActionMasked() == MotionEvent.ACTION_DOWN) {
            InputDevice device = event.getDevice();
            if (event.getDeviceId() <= 0 || device == null || device.isVirtual()) {
                reporter.report(Detection.of(Threat.EMULATED_INPUT, "deviceId:" + event.getDeviceId()));
                return true;
            }
        }
        return false;
    }

    private void refreshMirroring() {
        List<String> evidence = new ArrayList<>();
        for (Display display : displayManager.getDisplays()) {
            if (display.getDisplayId() != Display.DEFAULT_DISPLAY && (display.getFlags() & Display.FLAG_PRIVATE) == 0) {
                evidence.add("display:" + display.getName());
            }
        }
        boolean external = !evidence.isEmpty();
        if (external == mirroring) return;
        mirroring = external;
        Window window = activity.getWindow();
        if (external) {
            // Secure windows render black on every non-secure display (casting, Miracast, HDMI).
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
            reporter.report(new Detection(Threat.SCREEN_MIRRORING, evidence));
        } else if (config.allowScreenshot) {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }

    @Override
    public void onDisplayAdded(int displayId) {
        refreshMirroring();
    }

    @Override
    public void onDisplayRemoved(int displayId) {
        refreshMirroring();
    }

    @Override
    public void onDisplayChanged(int displayId) {
        refreshMirroring();
    }
}
