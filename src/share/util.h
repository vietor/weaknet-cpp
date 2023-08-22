#pragma once

void quit(const char *message);
void usage(const char *app, const char *format);

void parse_cmdline(int argc, char **argv, int *p_argc, char ***p_argv);
void parse_cmdline_free(int *p_argc, char ***p_argv);
