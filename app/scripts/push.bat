adb shell su 0 rm /data/local/tmp/injector /data/local/tmp/libinject-lib.so
adb push build\intermediates\stripped_native_libs\debug\out\lib\x86_64\libinjector.so /data/local/tmp/injector
adb push build\intermediates\stripped_native_libs\debug\out\lib\x86_64\libinject-lib.so /data/local/tmp/libinject-lib.so
adb shell su 0 chmod +x /data/local/tmp/injector
adb shell su 0 chcon u:object_r:system_file:s0 /data/local/tmp/libinject-lib.so
:: ./injector open `pidof zygote64` /data/local/tmp/libinject-lib.so