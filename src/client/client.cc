#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "local.h"
#include "../version.h"

int main(int argc, char *argv[]) {
  int opt;
  const char *short_options = "p:m:s:R:vh";
  struct option long_options[] = {{"port", required_argument, NULL, 'p'},
                                  {"algorithm", required_argument, NULL, 'm'},
                                  {"password", required_argument, NULL, 's'},
                                  {"remote-addr", required_argument, NULL, 'R'},
                                  {"version", no_argument, NULL, 'v'},
                                  {"help", no_argument, NULL, 'h'},
                                  {0, 0, 0, 0}};

  int parsed_argc = 0;
  char **parsed_argv = NULL;
  parse_cmdline(argc, argv, &parsed_argc, &parsed_argv);

  int port = 1080, remote_port = 51080;
  std::string algorithm, password, remote_addr;
  while ((opt = getopt_long(parsed_argc, parsed_argv, short_options,
                            long_options, NULL)) != -1) {
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

      case 'R':
        remote_addr = optarg;
        break;

      case 'v':
        quit("weaknet-client version " PROJECT_VERSION);
        break;

      default:
        usage(argv[0],
              "Usage: %s [options-file] [options]\n"
              "Options:\n"
              " -p or --port <port>, range 1-65535\n"
              " -m or --algorithm <algorithm>, support list:\n"
              "    chacha20, chacha20-ietf,\n"
              "    chacha20-ietf-poly1305,\n"
              "    xchacha20-ietf-poly1305\n"
              " -s or --password <password>\n"
              " -R or --remote-addr <ip:port>\n"
              " -v or --version\n"
              " -h or --help\n"
              "\n");
        break;
    }
  }

  parse_cmdline_free(&parsed_argc, &parsed_argv);

  if (port < 1 || port > 65535) {
    quit("invalid option: port");
  }

  if (algorithm.empty()) {
    quit("invalid option: algorithm");
  }

  if (password.empty()) {
    quit("invalid option: password");
  }

  if (remote_addr.empty()) {
    quit("invalid option: remote addr");
  }

  network_init();

  sockaddr_storage target_addr;
  int addr_len = sizeof(target_addr);

  if (evutil_parse_sockaddr_port(remote_addr.c_str(), (sockaddr *)&target_addr,
                                 &addr_len)) {
    quit("invalid option: remote addr");
  }
  if (target_addr.ss_family == AF_INET) {
    sockaddr_in *addr4 = (sockaddr_in *)&target_addr;
    if (!addr4->sin_port) {
      addr4->sin_port = htons(remote_port);
    }
  } else {
    sockaddr_in6 *addr6 = (sockaddr_in6 *)&target_addr;
    if (!addr6->sin6_port) {
      addr6->sin6_port = htons(remote_port);
    }
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

  LocalServer *server =
      new LocalServer(base, dnsbase, creator, port, &target_addr);
  if (!server->Startup(error)) {
    quit(error.c_str());
  }

  printf("listen on %d, algorithm: %s, remote: %s ...\n", port,
         algorithm.c_str(), remote_addr.c_str());

  event_base_dispatch(base);

  return 0;
}
