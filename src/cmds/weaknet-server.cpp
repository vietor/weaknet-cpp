#include <getopt.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../share/ProxyServer.h"
#include "../share/network.h"

void quit(const char *message)
{
  fprintf(stderr, message);
  exit(EXIT_FAILURE);
}

void usage(const char *app)
{
  const char *name = strrchr(app, PATH_SEPARATOR);
  if (name) {
    ++name;
  } else {
    name = app;
  }

  fprintf(stderr,
          "Usage: %s <options>\n"
          " -p or --port <port>, range 1-65535",
          name);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
#ifdef SYS_WINDOWS
  WORD wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;
  if (WSAStartup(wVersionRequested, &wsaData) != 0) {
    quit("WSAStartup failed.\n");
  }
#else
  signal(SIGPIPE, SIG_IGN);
#endif

  int opt;
  const char *short_options = "p:h";
  struct option long_options[] = {{"port", required_argument, NULL, 'p'}, {"help", no_argument, NULL, 'h'}, {0, 0, 0, 0}};

  int port = 58081;
  while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
    switch (opt) {
      case 'p':
        port = atoi(optarg);
        break;

      default:
        usage(argv[0]);
        break;
    }
  }

  if (port < 1 || port > 65535) {
    quit("invali option: -p or --port <port>, range 1-65535\n");
  }

  if (sodium_init()) {
    quit("sodium_init error");
  }

  event_base *base = event_base_new();
  if (!base) {
    quit("event_base_new error");
  }

  std::string error;

  ProxyServer *server = new ProxyServer(base, port);
  if (!server->Active(error)) {
    quit(error.c_str());
  }

  event_base_dispatch(base);

  return 0;
}
