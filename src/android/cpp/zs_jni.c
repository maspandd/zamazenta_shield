// JNI bridge for com.zamazenta.shield.NativeShield.
//
// Natives are bound with RegisterNatives, so no Java_* symbols are exported. Two background threads
// run independently of the Java scheduler: a watchdog repeating the runtime checks, and a
// /proc/self/mem watcher. When enforcing, any native detection also arms a fail-safe: if the Java
// side has not terminated the app within ZS_FAILSAFE_SECONDS (for example because it was patched
// out), the process exits through a raw exit_group syscall.
#include <jni.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

#include "zs_apksig.h"
#include "zs_checks.h"
#include "zs_sys.h"
#include "zs_util.h"

// Must match NativeShield flag constants.
#define ZS_CHECK_ROOT (1 << 0)
#define ZS_CHECK_TRACER (1 << 1)
#define ZS_CHECK_HOOKS (1 << 2)
#define ZS_CHECK_SIGNATURE (1 << 3)
#define ZS_WATCH_MEMORY (1 << 4)
#define ZS_HARDEN_PTRACE (1 << 5)
#define ZS_ENFORCE (1 << 6)

#define ZS_MAX_FINGERPRINTS 16
#define ZS_FAILSAFE_SECONDS 3

static JavaVM *g_vm;
static jclass g_bridge_class;
static jmethodID g_on_detections;

static struct {
    int flags;
    int interval_ms;
    int sdk_int;
    char package_name[256];
    char apk_path[1024];
    char fingerprints[ZS_MAX_FINGERPRINTS][ZS_SHA256_HEX_LEN + 1];
    size_t fingerprint_count;
} g_config;

static atomic_int g_started;
static atomic_int g_failsafe_armed;

// ---- Signature ----

// The APK the runtime actually mapped, taken from /proc/self/maps rather than from Java, where
// ApplicationInfo can be spoofed by a hooked PackageManager.
static void resolve_apk_path(const zs_maps *maps) {
    char needle[300];
    size_t used = zs_copy(needle, sizeof(needle), "/");
    used += zs_copy(needle + used, sizeof(needle) - used, g_config.package_name);
    zs_copy(needle + used, sizeof(needle) - used, "-");
    for (size_t i = 0; i < maps->count; i++) {
        const char *path = maps->items[i].path;
        if (zs_starts_with(path, "/data/app/") && zs_ends_with(path, "/base.apk") && zs_find(path, needle)) {
            zs_copy(g_config.apk_path, sizeof(g_config.apk_path), path);
            return;
        }
    }
}

static void check_signature(zs_report *report) {
    char actual[ZS_APK_MAX_SIGNERS][ZS_SHA256_HEX_LEN + 1];
    size_t count = 0;
    int rc = zs_apk_signer_fingerprints(g_config.apk_path, g_config.sdk_int, actual, &count);
    if (rc == ZS_APK_NO_SIGNING_BLOCK) {
        zs_report_add(report, ZS_CODE_REPACKAGED, "native-apk:", "no v2/v3 signature for this API level");
        return;
    }
    if (rc != ZS_APK_OK) {
        zs_report_add(report, ZS_CODE_REPACKAGED, "native-apk:", rc == ZS_APK_IO_ERROR ? "unreadable" : "malformed signing block");
        return;
    }
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < g_config.fingerprint_count; j++) {
            if (zs_mem_equal(actual[i], g_config.fingerprints[j], ZS_SHA256_HEX_LEN)) return;
        }
    }
    for (size_t i = 0; i < count; i++) zs_report_add(report, ZS_CODE_REPACKAGED, "native-signer:", actual[i]);
}

// ---- Checks ----

static void run_checks(int flags, int full, zs_report *report) {
    zs_maps maps;
    int have_maps = zs_maps_load(&maps) == 0;
    if (flags & ZS_CHECK_TRACER) zs_check_tracer(report);
    if (have_maps && (flags & ZS_CHECK_HOOKS)) {
        zs_check_frida(&maps, report);
        zs_check_inline_hooks(&maps, report);
        zs_check_injection(&maps, g_config.package_name, report);
    }
    if (full && (flags & ZS_CHECK_ROOT)) zs_check_root(report);
    if (full && (flags & ZS_CHECK_SIGNATURE) && g_config.apk_path[0]) check_signature(report);
    if (have_maps) zs_maps_free(&maps);
}

// ---- Fail-safe ----

static void *failsafe_main(void *unused) {
    (void) unused;
    struct timespec delay = {ZS_FAILSAFE_SECONDS, 0};
    while (nanosleep(&delay, &delay) != 0) {
    }
    zs_exit_group(0);
}

static void arm_failsafe(void) {
    if (!(g_config.flags & ZS_ENFORCE)) return;
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_failsafe_armed, &expected, 1)) return;
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread, &attr, failsafe_main, NULL) != 0) zs_exit_group(0);
    pthread_attr_destroy(&attr);
}

// ---- Java delivery ----

static jobjectArray to_java(JNIEnv *env, const zs_report *report) {
    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    if (!string_class) return NULL;
    jobjectArray array = (*env)->NewObjectArray(env, (jsize) report->count, string_class, NULL);
    (*env)->DeleteLocalRef(env, string_class);
    if (!array) return NULL;
    for (size_t i = 0; i < report->count; i++) {
        char line[ZS_ITEM_TEXT + 16];
        int code = report->items[i].code;
        size_t used = 0;
        // "<code>|<evidence>", code written without snprintf to keep the hot path libc-free.
        char digits[8];
        int nd = 0;
        do {
            digits[nd++] = (char) ('0' + code % 10);
            code /= 10;
        } while (code > 0 && nd < (int) sizeof(digits));
        while (nd > 0) line[used++] = digits[--nd];
        line[used++] = '|';
        zs_copy(line + used, sizeof(line) - used, report->items[i].text);
        jstring value = (*env)->NewStringUTF(env, line);
        if ((*env)->ExceptionCheck(env)) {
            // Evidence with invalid modified-UTF-8 (odd file names); drop the item.
            (*env)->ExceptionClear(env);
            continue;
        }
        (*env)->SetObjectArrayElement(env, array, (jsize) i, value);
        (*env)->DeleteLocalRef(env, value);
    }
    return array;
}

static void deliver(JNIEnv *env, const zs_report *report) {
    if (report->count == 0) return;
    jobjectArray items = to_java(env, report);
    if (items) {
        (*env)->CallStaticVoidMethod(env, g_bridge_class, g_on_detections, items);
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, items);
    }
    arm_failsafe();
}

// ---- Background threads ----

static void *watchdog_main(void *unused) {
    (void) unused;
    JNIEnv *env = NULL;
    if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) return NULL;
    struct timespec interval = {g_config.interval_ms / 1000, (long) (g_config.interval_ms % 1000) * 1000000L};
    for (;;) {
        struct timespec remaining = interval;
        while (nanosleep(&remaining, &remaining) != 0) {
        }
        zs_report report = {0};
        run_checks(g_config.flags, 0, &report);
        deliver(env, &report);
    }
    return NULL;
}

static void *memwatch_main(void *arg) {
    int fd = (int) (intptr_t) arg;
    JNIEnv *env = NULL;
    if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) {
        zs_close(fd);
        return NULL;
    }
    char detail[64];
    while (zs_memwatch_wait(fd, detail, sizeof(detail)) > 0) {
        zs_report report = {0};
        zs_report_add(&report, ZS_CODE_MEMORY_SCAN, "native-inotify:", detail);
        deliver(env, &report);
    }
    zs_close(fd);
    (*g_vm)->DetachCurrentThread(g_vm);
    return NULL;
}

static int spawn(void *(*entry)(void *), void *arg) {
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&thread, &attr, entry, arg);
    pthread_attr_destroy(&attr);
    return rc;
}

// ---- Natives ----

static void copy_jstring(JNIEnv *env, jstring value, char *out, size_t cap) {
    out[0] = '\0';
    if (!value) return;
    const char *chars = (*env)->GetStringUTFChars(env, value, NULL);
    if (!chars) return;
    zs_copy(out, cap, chars);
    (*env)->ReleaseStringUTFChars(env, value, chars);
}

static jboolean native_start(JNIEnv *env, jclass clazz, jint flags, jint interval_ms, jint sdk_int,
                             jstring package_name, jstring apk_path, jobjectArray fingerprints) {
    (void) clazz;
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_started, &expected, 1)) return JNI_TRUE;

    g_config.flags = flags;
    g_config.interval_ms = interval_ms;
    g_config.sdk_int = sdk_int;
    copy_jstring(env, package_name, g_config.package_name, sizeof(g_config.package_name));
    copy_jstring(env, apk_path, g_config.apk_path, sizeof(g_config.apk_path));
    jsize n = fingerprints ? (*env)->GetArrayLength(env, fingerprints) : 0;
    for (jsize i = 0; i < n && g_config.fingerprint_count < ZS_MAX_FINGERPRINTS; i++) {
        jstring item = (jstring) (*env)->GetObjectArrayElement(env, fingerprints, i);
        char *slot = g_config.fingerprints[g_config.fingerprint_count];
        copy_jstring(env, item, slot, ZS_SHA256_HEX_LEN + 1);
        (*env)->DeleteLocalRef(env, item);
        if (zs_strlen(slot) == ZS_SHA256_HEX_LEN) g_config.fingerprint_count++;
    }

    zs_maps maps;
    if (zs_maps_load(&maps) == 0) {
        resolve_apk_path(&maps);
        zs_maps_free(&maps);
    }

    // The inotify watch must be added while /proc/self/mem is still owned by our uid, i.e. before
    // PR_SET_DUMPABLE 0 hands procfs ownership to root.
    if (flags & ZS_WATCH_MEMORY) {
        int fd = zs_memwatch_open();
        if (fd >= 0 && spawn(memwatch_main, (void *) (intptr_t) fd) != 0) zs_close(fd);
    }
    // Non-dumpable: other non-root processes can no longer ptrace us or open /proc/<pid>/mem.
    if (flags & ZS_HARDEN_PTRACE) zs_prctl(PR_SET_DUMPABLE, 0);
    if (interval_ms > 0) spawn(watchdog_main, NULL);
    return JNI_TRUE;
}

static jobjectArray native_scan(JNIEnv *env, jclass clazz, jint flags) {
    (void) clazz;
    zs_report report = {0};
    run_checks(flags, 1, &report);
    jobjectArray items = to_java(env, &report);
    if (report.count > 0) arm_failsafe();
    return items;
}

static const JNINativeMethod g_methods[] = {
    {"nativeStart", "(IIILjava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z", (void *) native_start},
    {"nativeScan", "(I)[Ljava/lang/String;", (void *) native_scan},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    g_vm = vm;

    jclass local = (*env)->FindClass(env, "com/zamazenta/shield/NativeShield");
    if (!local) return JNI_ERR;
    g_bridge_class = (jclass) (*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    g_on_detections = (*env)->GetStaticMethodID(env, g_bridge_class, "onNativeDetections", "([Ljava/lang/String;)V");
    if (!g_on_detections) return JNI_ERR;
    if ((*env)->RegisterNatives(env, g_bridge_class, g_methods, sizeof(g_methods) / sizeof(g_methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
