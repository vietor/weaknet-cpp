#pragma once

#include "system.h"

#ifdef SYS_WINDOWS

#include <winsock2.h>
#include <ws2tcpip.h>

#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#endif

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/listener.h>

void network_init();

static inline bool bufferevent_output_busy(bufferevent* target) {
  return evbuffer_get_length(bufferevent_get_output(target)) >= 512 * 1024;
}
