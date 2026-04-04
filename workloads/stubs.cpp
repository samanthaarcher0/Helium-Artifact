// stubs.cpp
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

namespace mozilla {
    namespace detail {
        void InvalidArrayIndex_CRASH(unsigned long aIndex, unsigned long aLength) {
            abort();
        }
    }

    class PrintfTarget {
    public:
        PrintfTarget() {}
        bool vprint(const char* fmt, va_list args) {
            vfprintf(stderr, fmt, args);
            return true;
        }
    };
}
