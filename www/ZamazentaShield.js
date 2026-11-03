var exec = require('cordova/exec');

var SERVICE = 'ZamazentaShield';
var listeners = [];
var watching = false;

function call(action) {
    return new Promise(function (resolve, reject) {
        exec(resolve, reject, SERVICE, action, []);
    });
}

function dispatch(event) {
    listeners.slice().forEach(function (listener) {
        try {
            listener(event);
        } catch (e) {
            console.error('[ZamazentaShield] threat listener failed', e);
        }
    });
}

function ensureWatching() {
    if (watching) return;
    watching = true;
    exec(dispatch, function (error) {
        watching = false;
        console.warn('[ZamazentaShield] watch failed', error);
    }, SERVICE, 'watch', []);
}

module.exports = {
    /** Threat codes (AppShield-compatible; 40+ are ZamazentaShield extensions). */
    THREATS: {
        ROOTED: 0,
        JAILBROKEN: 0,
        REPACKAGED_ANDROID: 1,
        EMULATOR: 2,
        JAVA_DEBUGGER: 3,
        UNTRUSTED_KEYBOARD: 4,
        UNTRUSTED_SCREEN_READER: 5,
        NATIVE_HOOKS: 6,
        NATIVE_DEBUGGER: 9,
        HOOKING_FRAMEWORK_ANDROID: 22,
        VIRTUAL_SPACE: 29,
        EMULATED_INPUT: 31,
        PRIVATE_SPACE: 32,
        UNLOCKED_BOOTLOADER: 33,
        TAPJACKING: 34,
        CODE_INJECTION: 35,
        VPN: 37,
        DEVELOPER_MODE: 40,
        SCREEN_MIRRORING: 41,
        MEMORY_SCAN: 42,
        IOS_DEBUGGER: 1,
        IOS_REPACKAGED: 2,
        IOS_SCREENSHOT: 3,
        IOS_INJECTED_LIBRARY: 4,
        IOS_HOOKING_FRAMEWORK: 5,
        IOS_SCREEN_RECORDING: 6,
        IOS_RUNNING_ON_MAC: 7,
        IOS_SIMULATOR: 8
    },

    /** Configuration, enforcement mode and the result of the last full scan. */
    getStatus: function () {
        return call('getStatus');
    },

    /** Runs a full scan now. Enforcement still applies, so this may terminate the app. */
    check: function () {
        return call('check');
    },

    /**
     * Subscribes to detections. Events raised before the first subscription are buffered natively
     * and delivered on subscribe. Returns an unsubscribe function.
     */
    onThreat: function (listener) {
        if (typeof listener !== 'function') throw new TypeError('listener must be a function');
        listeners.push(listener);
        ensureWatching();
        return function unsubscribe() {
            var index = listeners.indexOf(listener);
            if (index >= 0) listeners.splice(index, 1);
        };
    }
};
