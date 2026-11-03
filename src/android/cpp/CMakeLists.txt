cmake_minimum_required(VERSION 3.18.1)
project(zshield C)

add_library(zshield SHARED
        zs_jni.c
        zs_checks.c
        zs_apksig.c
        zs_sha256.c
        zs_util.c)

set_target_properties(zshield PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)

target_compile_options(zshield PRIVATE
        -Wall -Wextra
        -O2
        -fvisibility=hidden
        -fstack-protector-strong
        -ffunction-sections -fdata-sections)

target_link_options(zshield PRIVATE
        -Wl,--gc-sections
        -Wl,--exclude-libs,ALL
        # 16 KB page-size devices (Android 15+, required by Play for new apps).
        -Wl,-z,max-page-size=16384
        -Wl,-z,relro -Wl,-z,now)

target_link_libraries(zshield PRIVATE dl)
