#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "system.h"

void quit(const char *message) {
  fprintf(stderr, "%s\n", message);
  exit(EXIT_FAILURE);
}

void usage(const char *app, const char *format) {
  const char *name = strrchr(app, PATH_SEPARATOR);
  if (name) {
    ++name;
  } else {
    name = app;
  }

  fprintf(stderr, format, name);
  exit(EXIT_FAILURE);
}
