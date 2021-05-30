#include "proxy_server.h"

ProxyServer::ProxyServer(event_base *base, unsigned short port) : base_(base), port_(port) {}

ProxyServer::~ProxyServer() {}

bool ProxyServer::Active(std::string &error)
{
  sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(port_);
  listener_ = evconnlistener_new_bind(base_, OnConnected, this, LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, 128, (sockaddr *)&sin, sizeof(sin));
  if (!listener_) {
    error = "bad listen on port: " + std::to_string(port_);
    return false;
  }
  return true;
}

void ProxyServer::OnConnected(evconnlistener *listen, evutil_socket_t sock, struct sockaddr *addr, int len, void *ctx)
{
  ((ProxyServer *)ctx)->HandleConnected(sock, addr, len);
}

void ProxyServer::HandleConnected(evutil_socket_t sock, struct sockaddr *addr, int len) {}
