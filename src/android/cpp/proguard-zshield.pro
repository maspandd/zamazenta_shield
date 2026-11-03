# libzshield binds natives by name (RegisterNatives) and calls back into onNativeDetections.
-keepclassmembers,includedescriptorclasses class com.zamazenta.shield.NativeShield {
    native <methods>;
    static void onNativeDetections(java.lang.String[]);
}
-keep class com.zamazenta.shield.NativeShield
# Cordova instantiates plugins reflectively from config.xml.
-keep class com.zamazenta.shield.ZamazentaShield { public <init>(); }
