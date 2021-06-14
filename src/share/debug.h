#pragma once

#ifdef NDEBUG
#define USE_DEBUG 0

#define dump()
#define dump_bin()

#else
#define USE_DEBUG 1

void dump(const char* format, ...);
void dump_hex(const char* data, int size, const char* title);

#endif
