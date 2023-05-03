#include <jni.h>
#include <string>
#include "logging.h"

[[gnu::constructor]]
void init() {
    LOGD("injected");
}

[[gnu::destructor]]
void fini() {
    LOGD("closed");
}