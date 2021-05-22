#include "network.h"

class ProxyLocalClient
{
 public:
  ProxyLocalClient(bufferevent *client);
  ~ProxyLocalClient();

  void Active();

 private:
  static void OnClientRead(bufferevent *bev, void *ctx);
  static void OnClientWrite(bufferevent *bev, void *ctx);
  static void OnClientEvent(bufferevent *bev, short what, void *ctx);

  bufferevent *client_;
};
