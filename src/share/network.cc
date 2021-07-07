#include "network.h"

void network_init() {
#ifdef SYS_WINDOWS
  WORD wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#else
  signal(SIGPIPE, SIG_IGN);
#endif
}
