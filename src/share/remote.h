#pragma once

#include "stream.h"

class RemoteServer
{
 public:
  RemoteServer(event_base *base, evdns_base *dnsbase, StreamCipher *cipher, unsigned short port);
  ~RemoteServer();

  bool Startup(std::string &error);

 private:
  static void OnConnected(evconnlistener *listen, evutil_socket_t sock, struct sockaddr *addr, int len, void *ctx);
  void HandleConnected(evutil_socket_t sock, struct sockaddr *addr, int len);

  event_base *base_;
  evdns_base *dnsbase_;
  StreamCipher *cipher_;
  unsigned short port_;
  evconnlistener *listener_ = nullptr;
};

class RemoteClient
{
  enum RunStep { STEP_INIT = 0, STEP_CONNECT, STEP_TRANSPORT };

 public:
  RemoteClient(event_base *base, evdns_base *dnsbase, bufferevent *client, StreamCrypto *crypto);

  void Startup();

 private:
  ~RemoteClient();
  void Cleanup();

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
  bufferevent *client_;
  StreamCrypto *crypto_;
  RunStep step_ = STEP_INIT;
  evbuffer *pedding_ = nullptr;
  bufferevent *target_ = nullptr;
};
