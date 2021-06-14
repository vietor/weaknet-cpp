#include "remote.h"

#define MAX_OUTPUT (512 * 1024)

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

  RemoteClient *client = new RemoteClient(base_, dnsbase_, cipher_->NewCrypto(), event);
  client->Startup();
}

RemoteClient::RemoteClient(event_base *base, evdns_base *dnsbase, StreamCrypto *crypto, bufferevent *client)
    : base_(base), dnsbase_(dnsbase), crypto_(crypto), client_(client)
{
}

RemoteClient::~RemoteClient()
{
  bufferevent_free(client_);
  if (target_) {
    bufferevent_free(target_);
  }
  if (target_cached_) {
    evbuffer_free(target_cached_);
  }
  crypto_->Release();
}

void RemoteClient::Startup()
{
  bufferevent_setcb(client_, OnClientRead, OnClientWrite, OnClientEvent, this);
  bufferevent_enable(client_, EV_READ | EV_WRITE);
}

void RemoteClient::Cleanup(const char *reason)
{
  dump("cleanup: client: %d, target: %d, step: %d, %s\n", bufferevent_getfd(client_), target_ ? bufferevent_getfd(target_) : 0, step_, reason);
  step_ = STEP_TERMINATE;
  delete this;
}

void RemoteClient::OnClientRead(bufferevent *bev, void *ctx)
{
  RemoteClient *self = (RemoteClient *)ctx;
  evbuffer *buf = evbuffer_new();
  int ret = bufferevent_read_buffer(bev, buf);
  if (ret == 0)
    self->HandleClientRead(buf);
  else {
    evbuffer_free(buf);
    self->Cleanup("error: client read");
  }
}

void RemoteClient::OnClientWrite(bufferevent *bev, void *ctx) { ((RemoteClient *)ctx)->HandleClientEmpty(); }

void RemoteClient::OnClientEvent(bufferevent *bev, short what, void *ctx)
{
  RemoteClient *self = (RemoteClient *)ctx;
  if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    self->Cleanup("client closed");
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
    self->Cleanup("error: target read");
  }
}

void RemoteClient::OnTargetWrite(bufferevent *bev, void *ctx) { ((RemoteClient *)ctx)->HandleTargetEmpty(); }

void RemoteClient::OnTargetEvent(bufferevent *bev, short what, void *ctx)
{
  RemoteClient *self = (RemoteClient *)ctx;
  if (what & BEV_EVENT_CONNECTED) {
    self->HandleTargetReady();
  } else if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
    self->Cleanup("target closed");
  }
}

void RemoteClient::HandleClientRead(evbuffer *buf)
{
  evbuffer *decoded = crypto_->Decrypt(buf);
  evbuffer_free(buf);
  if (!decoded) {
    Cleanup("error: client decrypt");
    return;
  }

  std::unique_ptr<evbuffer, void (*)(evbuffer *)> decoded_clear(decoded, &evbuffer_free);

  if (step_ == STEP_INIT) {
    int data_len = evbuffer_get_length(decoded);
    if (data_len < 2) {
      Cleanup("error: proxy header #1");
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
      Cleanup("error proxy header #2");
      return;
    }

    unsigned short port = ntohs(*(unsigned short *)(data + addr_pos + addr_len));
    if (!port) {
      Cleanup("error proxy header #3");
      return;
    }

    target_ = bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE);
    if (!target_) {
      Cleanup("incredible: bufferevent_socket_new");
      return;
    }

    step_ = STEP_CONNECT;
    bufferevent_setcb(target_, OnTargetRead, OnTargetWrite, OnTargetEvent, this);
    bufferevent_enable(target_, EV_READ | EV_WRITE);
    if (type == 3) {
      data[addr_pos + addr_len] = '\0';
      dump("connect host: %s, port: %d\n", data, port);
      bufferevent_socket_connect_hostname(target_, dnsbase_, AF_UNSPEC, (char *)(data + addr_pos), port);
    } else {
      sockaddr_storage sa;
      memset(&sa, 0, sizeof(sa));
#if USE_DEBUG
      char addrbuf[INET6_ADDRSTRLEN];
#endif
      if (type == 1) {
        sockaddr_in *sin = (sockaddr_in *)&sa;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr.s_addr, data + addr_pos, addr_len);
        sin->sin_port = htons(port);
        dump("connect ipv4: %s, port: %d\n", evutil_inet_ntop(AF_INET, &sin->sin_addr, addrbuf, sizeof(addrbuf)), port);
      } else {
        sockaddr_in6 *sin6 = (sockaddr_in6 *)&sa;
        sin6->sin6_family = AF_INET6;
        memcpy(sin6->sin6_addr.s6_addr, data + addr_pos, addr_len);
        sin6->sin6_port = htons(port);
        dump("connect ipv6: %s, port: %d\n", evutil_inet_ntop(AF_INET, &sin6->sin6_addr, addrbuf, sizeof(addrbuf)), port);
      }
      bufferevent_socket_connect(target_, (sockaddr *)&sa, sizeof(sa));
    }

    if (drain_len < data_len) {
      evbuffer_drain(decoded, drain_len);
      target_cached_ = decoded;
      decoded_clear.release();
    }
  } else if (step_ == STEP_CONNECT) {
    if (!target_cached_) {
      target_cached_ = decoded;
      decoded_clear.release();
    } else {
      evbuffer_add_buffer(target_cached_, decoded);
    }
  } else {
    bufferevent_write_buffer(target_, decoded);

    if (evbuffer_get_length(bufferevent_get_output(target_)) > MAX_OUTPUT) {
      target_busy_ = true;
      bufferevent_disable(client_, EV_READ);
    }
  }
}

void RemoteClient::HandleClientEmpty()
{
  if (step_ == STEP_TRANSPORT && client_busy_) {
    client_busy_ = false;
    bufferevent_enable(target_, EV_READ);
  }
}

void RemoteClient::HandleTargetReady()
{
  step_ = STEP_TRANSPORT;
  if (target_cached_) {
    bufferevent_write_buffer(target_, target_cached_);
    evbuffer_free(target_cached_);
    target_cached_ = nullptr;
  }
}

void RemoteClient::HandleTargetRead(evbuffer *buf)
{
  evbuffer *encoded = crypto_->Encrypt(buf);
  evbuffer_free(buf);
  if (!encoded) {
    Cleanup("error: target encrypt");
    return;
  }

  bufferevent_write_buffer(client_, encoded);
  evbuffer_free(encoded);

  if (evbuffer_get_length(bufferevent_get_output(client_)) > MAX_OUTPUT) {
    client_busy_ = true;
    bufferevent_disable(target_, EV_READ);
  }
}

void RemoteClient::HandleTargetEmpty()
{
  if (step_ == STEP_TRANSPORT && target_busy_) {
    target_busy_ = false;
    bufferevent_enable(client_, EV_READ);
  }
}
