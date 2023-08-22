#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <ctype.h>

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

void parse_cmdline_arguments(int argc, char **argv, int *p_argc,
                             char ***p_argv) {
  int i;
  std::vector<char *> arguments;

  FILE *fp = nullptr;
  for (i = 0; i < argc; ++i) {
    if (i == 1 && argv[i][0] != '-') {
      fp = fopen(argv[i], "r");
      if (fp != nullptr) {
        continue;
      }
    }

    arguments.push_back(strdup(argv[i]));
  }

  if (fp != nullptr) {
    int c, n;
    char buffer[1024];

    n = 0;
    while ((c = fgetc(fp)) != EOF) {
      if (!isblank(c) && !isspace(c)) {
        buffer[n++] = c;
      } else {
        if (n > 0) {
          buffer[n] = 0;
          arguments.push_back(strdup(buffer));
          n = 0;
        }
      }
    }
    if (n > 0) {
      buffer[n] = 0;
      arguments.push_back(strdup(buffer));
    }

    fclose(fp);
    fp = nullptr;
  }

  int parsed_argc = arguments.size();
  char **parsed_argv = (char **)malloc(sizeof(char *) * parsed_argc);
  for (i = 0; i < parsed_argc; ++i) {
    parsed_argv[i] = arguments.at(i);
  }

  *p_argc = parsed_argc;
  *p_argv = parsed_argv;
}

void parse_cmdline_free(int *p_argc, char ***p_argv) {
  for (int i = 0; i < *p_argc; ++i) {
    free((*p_argv)[i]);
  }

  free(*p_argv);
  *p_argc = 0;
  *p_argv = nullptr;
}
