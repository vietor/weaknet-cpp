#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "../share/remote.h"

int main(int argc, char *argv[]) {
  network_init();

  int opt;
  const char *short_options = "p:m:s:h";
  struct option long_options[] = {{"port", required_argument, NULL, 'p'},
                                  {"algorithm", required_argument, NULL, 'm'},
                                  {"password", required_argument, NULL, 's'},
                                  {"help", no_argument, NULL, 'h'},
                                  {0, 0, 0, 0}};

  int port = 51080;
  std::string algorithm, password;
  while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) !=
         -1) {
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
        usage(argv[0],
              "Usage: %s <options>\n"
              "Options:\n"
              " -p or --port <port>, range 1-65535\n"
              " -m or --algorithm <algorithm>, support list:\n"
              "    chacha20, chacha20-ietf,\n"
              "    chacha20-ietf-poly1305,\n"
              "    xchacha20-ietf-poly1305\n"
              " -s or --password <password>\n"
              " -h or --help\n"
              "\n");
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

  std::string error;

  if (!CryptoCreator::Init(error)) {
    quit(error.c_str());
  }

  CryptoCreator *creator =
      CryptoCreator::NewInstance(algorithm.c_str(), password.c_str());
  if (!creator) {
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

  RemoteServer *server = new RemoteServer(base, dnsbase, creator, port);
  if (!server->Startup(error)) {
    quit(error.c_str());
  }

  printf("listen on %d, algorithm: %s ...\n", port, algorithm.c_str());

  event_base_dispatch(base);

  return 0;
}
