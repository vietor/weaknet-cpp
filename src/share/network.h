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
#include <event2/event_struct.h>
#include <event2/listener.h>

#include <memory>
#include <string>
#include <string.h>
