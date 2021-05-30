#pragma once

#include "proxy_local_client.h"

class ProxyServer
{
 public:
  ProxyServer(event_base *base, unsigned short port);
  ~ProxyServer();

  bool Active(std::string &error);

 private:
  static void OnConnected(evconnlistener *listen, evutil_socket_t sock, struct sockaddr *addr, int len, void *ctx);
  void HandleConnected(evutil_socket_t sock, struct sockaddr *addr, int len);

  event_base *base_;
  unsigned short port_;
  evconnlistener *listener_ = nullptr;
};
