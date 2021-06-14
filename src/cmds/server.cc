#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "../share/remote.h"
#include "../share/stream.h"

void quit(const char *message)
{
  fprintf(stderr, "%s\n", message);
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
          "Options:\n"
          " -p or --port <port>, range 1-65535\n"
          " -m or --algorithm <algorithm>\n"
          "    supported: chcha20, chch20-ietf\n"
          " -s or --password <password>\n"
          " - or --help\n"
          "\n",
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
  const char *short_options = "p:m:s:h";
  struct option long_options[] = {{"port", required_argument, NULL, 'p'},
                                  {"algorithm", required_argument, NULL, 'm'},
                                  {"password", required_argument, NULL, 's'},
                                  {"help", no_argument, NULL, 'h'},
                                  {0, 0, 0, 0}};

  int port = 51080;
  std::string algorithm, password;
  while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
    switch (opt) {
      case 'p':
        port = atoi(optarg);
        break;

      case 'm':
        algorithm = optarg;
        break;

      case 's':
        password = optarg;
        break;

      default:
        usage(argv[0]);
        break;
    }
  }

  if (port < 1 || port > 65535) {
    quit("invalid option: port");
  }

  if (algorithm.empty()) {
    quit("invalid option: algorithm");
  }

  if (password.empty()) {
    quit("invalid option: password");
  }

  if (sodium_init()) {
    quit("incredible: sodium_init error");
  }

  StreamCipher *cipher = StreamCipher::NewInstance(algorithm.c_str(), password.c_str());
  if (!cipher) {
    quit("invalid option: algorithm, not supported");
  }

  event_base *base = event_base_new();
  if (!base) {
    quit("incredible: event_base_new error");
  }

  evdns_base *dnsbase = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
  if (!dnsbase) {
    quit("incredible: evdns_base_new error");
  }

  std::string error;

  RemoteServer *server = new RemoteServer(base, dnsbase, cipher, port);
  if (!server->Startup(error)) {
    quit(error.c_str());
  }

  printf("listen on %d, algorithm: %s ...\n", port, algorithm.c_str());

  event_base_dispatch(base);

  return 0;
}
