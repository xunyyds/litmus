cmake_minimum_required(VERSION 3.22.1)
project(litmusprobe CXX)

# 构建：canary/build.ps1 会对每个 ABI 各调一次，产物 liblitmusprobe.so
# 手工：
#   cmake -S . -B ../build/native/arm64-v8a \
#         -DCMAKE_TOOLCHAIN_FILE=$env:ANDROID_NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
#         -DCMAKE_BUILD_TYPE=Release
#   cmake --build ../build/native/arm64-v8a

add_library(litmusprobe SHARED
        litmus_probe.cpp
        elf_scan.cpp)

target_compile_features(litmusprobe PRIVATE cxx_std_17)
target_compile_options(litmusprobe PRIVATE
        -Wall -Wextra -Wno-unused-parameter
        -fvisibility=hidden
        -fno-exceptions -fno-rtti)

find_library(LOG_LIB log)
# dladdr() 用来定位自己这个 .so（gotCheck 需要自己的 load bias）
find_library(DL_LIB dl)
target_link_libraries(litmusprobe ${LOG_LIB} ${DL_LIB})

set_target_properties(litmusprobe PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
        OUTPUT_NAME "litmusprobe")
