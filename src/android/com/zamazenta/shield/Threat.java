package com.zamazenta.shield;

/**
 * Threat codes. Values 0-37 reuse the OutSystems AppShield Android shutdown codes so
 * existing ExitOnURL landing pages (which read the {@code reason} parameter) keep working.
 * Codes 40 and above are ZamazentaShield extensions for threats AppShield blocks without a code.
 */
enum Threat {
    ROOTED(0, "rooted", "Device is rooted", false),
    REPACKAGED(1, "repackaged", "Application is modified or repackaged", false),
    EMULATOR(2, "emulator", "Application is being run in an emulator", false),
    JAVA_DEBUGGER(3, "java_debugger", "Java debugger attached to app", false),
    UNTRUSTED_KEYBOARD(4, "untrusted_keyboard", "Untrusted keyboard detected", false),
    UNTRUSTED_SCREEN_READER(5, "untrusted_screen_reader", "Untrusted screen reader detected", false),
    NATIVE_HOOKS(6, "native_hooks", "Native code hooks detected", false),
    NATIVE_DEBUGGER(9, "native_debugger", "Native debugger attached to app", false),
    HOOKING_FRAMEWORK(22, "hooking_framework", "Hooking frameworks detected", false),
    VIRTUAL_SPACE(29, "virtual_space", "Application launched via a virtual space application", false),
    EMULATED_INPUT(31, "emulated_input", "Emulated input detected", false),
    PRIVATE_SPACE(32, "private_space", "Application launched in a Private Space or Work Profile", false),
    UNLOCKED_BOOTLOADER(33, "unlocked_bootloader", "Device bootloader is unlocked", false),
    TAPJACKING(34, "tapjacking", "Tapjacking event detected", true),
    CODE_INJECTION(35, "code_injection", "Code injected into the application process", false),
    VPN(37, "vpn", "Device connected to a VPN", false),
    DEVELOPER_MODE(40, "developer_mode", "Developer options or USB debugging enabled", false),
    SCREEN_MIRRORING(41, "screen_mirroring", "App content routed to a secondary display", true),
    MEMORY_SCAN(42, "memory_scan", "Process memory is being scanned or dumped", false);

    final int code;
    final String id;
    final String description;
    /** Neutralised in place (input dropped, display blanked) rather than by terminating the app. */
    final boolean mitigatedInPlace;

    Threat(int code, String id, String description, boolean mitigatedInPlace) {
        this.code = code;
        this.id = id;
        this.description = description;
        this.mitigatedInPlace = mitigatedInPlace;
    }

    static Threat fromCode(int code) {
        for (Threat threat : values()) {
            if (threat.code == code) return threat;
        }
        return null;
    }
}
