#include "debug.h"

#if USE_DEBUG

#include <stdarg.h>
#include <stdio.h>

#include <string>

void dump(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
}

void dump_hex(const void* data, int size, const char* title) {
  char tmp[32];
  std::string out;

  if (title) {
    out += title;
  }

  for (int i = 0; i < size; ++i) {
    if (i % 16 == 0) {
      out += "\n";
      sprintf(tmp, "%04X", (unsigned int)i);
      out += tmp;
    }
    sprintf(tmp, " %02X", ((unsigned char*)data)[i]);
    out += tmp;
  }

  if (out.back() != '\n') out += "\n";

  fputs(out.c_str(), stderr);
}

#endif
