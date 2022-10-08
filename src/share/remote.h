#pragma once

#include "client.h"
#include "crypto.h"

class RemoteServer {
 public:
  RemoteServer(event_base *base, evdns_base *dnsbase, CryptoCreator *creator,
               unsigned short port);
  ~RemoteServer();

  bool Startup(std::string &error);

 private:
  static void OnConnected(evconnlistener *listen, evutil_socket_t sock,
                          sockaddr *addr, int len, void *ctx);

  void HandleConnected(evutil_socket_t sock);

  event_base *base_;
  evdns_base *dnsbase_;
  CryptoCreator *creator_;
  unsigned short port_;
  evconnlistener *listener_ = nullptr;
};

class RemoteClient {
 public:
  RemoteClient(event_base *base, evdns_base *dnsbase, Crypto *crypto,
               bufferevent *client);

  void Startup();

 private:
  ~RemoteClient();
  void Cleanup(const char *reason);

  static void OnClientRead(bufferevent *bev, void *ctx);
  static void OnClientWrite(bufferevent *bev, void *ctx);
  static void OnClientEvent(bufferevent *bev, short what, void *ctx);
  static void OnTargetRead(bufferevent *bev, void *ctx);
  static void OnTargetWrite(bufferevent *bev, void *ctx);
  static void OnTargetEvent(bufferevent *bev, short what, void *ctx);

  void HandleClientRead(evbuffer *buf);
  void HandleClientEmpty();
  void HandleTargetReady();
  void HandleTargetRead(evbuffer *buf);
  void HandleTargetEmpty();

  event_base *base_;
  evdns_base *dnsbase_;
  Crypto *crypto_;
  bufferevent *client_;
  RuningStep step_ = STEP_INIT;
  bufferevent *target_ = nullptr;
  evbuffer *target_cached_ = nullptr;
  bool client_busy_ = false;
  bool target_busy_ = false;

  size_t client_read_bytes_ = 0;
  size_t client_write_bytes_ = 0;
  size_t target_read_bytes_ = 0;
  size_t target_write_bytes_ = 0;
};
