#include "remote.h"

#include <event2/bufferevent.h>

RemoteServer::RemoteServer(event_base *base, evdns_base *dnsbase, StreamCipher *cipher, unsigned short port)
    : base_(base), dnsbase_(dnsbase), cipher_(cipher), port_(port)
{
}

RemoteServer::~RemoteServer() {}

bool RemoteServer::Startup(std::string &error)
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

void RemoteServer::OnConnected(evconnlistener *listen, evutil_socket_t sock, struct sockaddr *addr, int len, void *ctx)
{
  ((RemoteServer *)ctx)->HandleConnected(sock, addr, len);
}

void RemoteServer::HandleConnected(evutil_socket_t sock, struct sockaddr *addr, int len)
{
  struct bufferevent *event = bufferevent_socket_new(base_, sock, BEV_OPT_CLOSE_ON_FREE);
  if (!event) {
    evutil_closesocket(sock);
    return;
  }

  RemoteClient *client = new RemoteClient(base_, dnsbase_, event, cipher_->NewCrypto());
  client->Startup();
}

RemoteClient::RemoteClient(event_base *base, evdns_base *dnsbase, bufferevent *client, StreamCrypto *crypto)
    : base_(base), dnsbase_(dnsbase), client_(client), crypto_(crypto)
{
}

RemoteClient::~RemoteClient()
{
  bufferevent_free(client_);
  if (pedding_) {
    evbuffer_free(pedding_);
  }
  if (target_) {
    bufferevent_free(target_);
  }
}

void RemoteClient::Startup()
{
  bufferevent_setcb(client_, OnClientRead, NULL, OnClientEvent, this);
  bufferevent_enable(client_, EV_READ);
}

void RemoteClient::Cleanup() { delete this; }

void RemoteClient::OnClientRead(bufferevent *bev, void *ctx)
{
  RemoteClient *self = (RemoteClient *)ctx;
  evbuffer *buf = evbuffer_new();
  int ret = bufferevent_read_buffer(bev, buf);
  if (ret == 0)
    self->HandleClientRead(buf);
  else {
    evbuffer_free(buf);
    self->Cleanup();
  }
}

void RemoteClient::OnClientEvent(bufferevent *bev, short what, void *ctx)
{
  RemoteClient *self = (RemoteClient *)ctx;
  if (what & BEV_EVENT_ERROR) {
    self->Cleanup();
  }
}

void RemoteClient::OnTargetRead(bufferevent *bev, void *ctx)
{
  RemoteClient *self = (RemoteClient *)ctx;
  evbuffer *buf = evbuffer_new();
  int ret = bufferevent_read_buffer(bev, buf);
  if (ret == 0)
    self->HandleTargetRead(buf);
  else {
    evbuffer_free(buf);
    self->Cleanup();
  }
}

void RemoteClient::OnTargetEvent(bufferevent *bev, short what, void *ctx)
{
  RemoteClient *self = (RemoteClient *)ctx;
  if (what & BEV_EVENT_CONNECTED) {
    self->HandleTargetReady();
  } else if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
    self->Cleanup();
  }
}

void RemoteClient::HandleClientRead(evbuffer *buf)
{
  evbuffer *decoded = crypto_->Decrypt(buf);
  evbuffer_free(buf);
  if (!decoded) {
    Cleanup();
    return;
  }

  std::unique_ptr<evbuffer, void (*)(evbuffer *)> decoded_clear(decoded, &evbuffer_free);

  if (step_ == STEP_INIT) {
    int data_len = evbuffer_get_length(decoded);
    if (data_len < 2) {
      Cleanup();
      return;
    }

    unsigned char *data = evbuffer_pullup(decoded, data_len);
    int type = data[0], addr_pos = 1, addr_len = 0;
    switch (type) {
      case 1:  // IPV4
        addr_len = 4;
        break;
      case 3:  // Domain
        addr_pos = 2;
        addr_len = data[1];
        break;
      case 4:  // IPV6
        addr_len = 16;
        break;
      default:
        break;
    }

    int drain_len = addr_pos + addr_len + 2;
    if (addr_len < 1 || drain_len > data_len) {
      Cleanup();
      return;
    }

    unsigned short port = ntohs(*(unsigned short *)(data + addr_pos + addr_len));
    if (!port) {
      Cleanup();
      return;
    }

    target_ = bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE);
    if (!target_) {
      Cleanup();
      return;
    }

    step_ = STEP_CONNECT;
    bufferevent_setcb(target_, OnTargetRead, NULL, OnTargetEvent, base_);
    bufferevent_enable(target_, EV_READ | EV_WRITE);
    if (type == 3) {
      bufferevent_socket_connect_hostname(target_, dnsbase_, AF_UNSPEC, (char *)(data + addr_pos), port);
    } else {
      sockaddr_storage sa;
      memset(&sa, 0, sizeof(sa));
      if (type == 1) {
        sockaddr_in *sin = (sockaddr_in *)&sa;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr.s_addr, data + addr_pos, addr_len);
        sin->sin_port = htons(port);
      } else {
        sockaddr_in6 *sin6 = (sockaddr_in6 *)&sa;
        sin6->sin6_family = AF_INET6;
        memcpy(sin6->sin6_addr.s6_bytes, data + addr_pos, addr_len);
        sin6->sin6_port = htons(port);
      }
      bufferevent_socket_connect(target_, (sockaddr *)&sa, sizeof(sa));
    }

    if (drain_len < data_len) {
      evbuffer_drain(decoded, drain_len);
      pedding_ = decoded;
      decoded_clear.release();
    }

  } else if (step_ == STEP_CONNECT) {
    if (!pedding_) {
      pedding_ = decoded;
      decoded_clear.release();
    } else {
      evbuffer_add_buffer(pedding_, decoded);
    }
  } else {
    bufferevent_write_buffer(target_, decoded);
  }
}

void RemoteClient::HandleTargetReady()
{
  step_ = STEP_TRANSPORT;
  if (pedding_) {
    bufferevent_write_buffer(target_, pedding_);
    evbuffer_free(pedding_);
    pedding_ = nullptr;
  }
}

void RemoteClient::HandleTargetRead(evbuffer *buf)
{
  evbuffer *encoded = crypto_->Encrypt(buf);
  evbuffer_free(buf);
  if (!encoded) {
    Cleanup();
    return;
  }

  bufferevent_write_buffer(client_, encoded);
  evbuffer_free(encoded);
}
