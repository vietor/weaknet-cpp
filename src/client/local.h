#pragma once

#include "../share/crypto.h"
#include "../share/protocol.h"

class LocalServer {
 public:
  LocalServer(event_base *base, evdns_base *dnsbase, CryptoCreator *creator,
              unsigned short port, const sockaddr_storage *remote_addr);
  ~LocalServer();

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
  const sockaddr_storage *remote_addr_ = nullptr;
};

class LocalClient {
 public:
  LocalClient(event_base *base, evdns_base *dnsbase, Crypto *crypto,
              bufferevent *client, const sockaddr_storage *remote_addr);

  void Startup();

 private:
  ~LocalClient();
  void Cleanup(const char *reason);

  void ConnectTarget();

  static void OnClientRead(bufferevent *bev, void *ctx);
  static void OnClientWrite(bufferevent *bev, void *ctx);
  static void OnClientEvent(bufferevent *bev, short what, void *ctx);
  static void OnTargetRead(bufferevent *bev, void *ctx);
  static void OnTargetWrite(bufferevent *bev, void *ctx);
  static void OnTargetEvent(bufferevent *bev, short what, void *ctx);

  void HandleClientRead(evbuffer *buf);
  void HandleClientEmpty();
  void HandleClientClose();
  void HandleTargetReady();
  void HandleTargetRead(evbuffer *buf);
  void HandleTargetEmpty();
  void HandleTargetClose();

  void ProcessProtocolSOCKS4(unsigned char *data, int data_len);
  void ProcessProtocolSOCKS5(unsigned char *data, int data_len);
  void ProcessProtocolCONNECT(unsigned char *data, int data_len);
  void ProcessProtocolPROXY(unsigned char *data, int data_len);

  event_base *base_;
  evdns_base *dnsbase_;
  Crypto *crypto_;
  bufferevent *client_;
  const sockaddr_storage *remote_addr_ = nullptr;
  mutable RuningStep step_ = STEP_INIT;
  RuningProtocol protocol_ = PROTOCOL_NONE;
  bufferevent *target_ = nullptr;
  evbuffer *target_cached_ = nullptr;
  bool client_busy_ = false;
  bool target_busy_ = false;

#if USE_DEBUG
  size_t client_read_bytes_ = 0;
  size_t client_write_bytes_ = 0;
  size_t target_read_bytes_ = 0;
  size_t target_write_bytes_ = 0;
#endif
};
