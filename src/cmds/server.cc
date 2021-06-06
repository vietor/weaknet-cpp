#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../share/remote.h"
#include "../share/stream.h"

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
          " -P or --port <port>, range 1-65535\n"
          " -a or --algorithm <algorithm>\n"
          " -p or --password <password>",
          name);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
#ifdef SYS_WINDOWS
  WORD wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#else
  signal(SIGPIPE, SIG_IGN);
#endif

  int opt;
  const char *short_options = "p:a:P:h";
  struct option long_options[] = {{"port", required_argument, NULL, 'P'},
                                  {"algorithm", required_argument, NULL, 'a'},
                                  {"password", required_argument, NULL, 'p'},
                                  {"help", no_argument, NULL, 'h'},
                                  {0, 0, 0, 0}};

  int port = 58081;
  std::string algorithm("chacha20-ietf"), password("w*akn*ts*cr*t");
  while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
    switch (opt) {
      case 'P':
        port = atoi(optarg);
        break;

      case 'a':
        algorithm = optarg;
        break;

      case 'p':
        password = optarg;
        break;

      default:
        usage(argv[0]);
        break;
    }
  }

  if (port < 1 || port > 65535) {
    quit("invali option: port\n");
  }

  if (algorithm.empty()) {
    quit("invali option: algorithm\n");
  }

  if (password.empty()) {
    quit("invali option: password\n");
  }

  if (sodium_init()) {
    quit("sodium_init error");
  }

  StreamCipher *cipher = StreamCipher::NewInstance(algorithm.c_str(), password.c_str());

  event_base *base = event_base_new();
  if (!base) {
    quit("event_base_new error");
  }

  evdns_base *dnsbase = evdns_base_new(base, 1);
  if (!dnsbase) {
    quit("evdns_base_new error");
  }

  std::string error;

  RemoteServer *server = new RemoteServer(base, dnsbase, cipher, port);
  if (!server->Startup(error)) {
    quit(error.c_str());
  }

  event_base_dispatch(base);

  return 0;
}
