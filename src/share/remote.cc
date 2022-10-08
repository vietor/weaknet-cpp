#include "remote.h"

RemoteServer::RemoteServer(event_base *base, evdns_base *dnsbase,
                           CryptoCreator *creator, unsigned short port)
    : base_(base), dnsbase_(dnsbase), creator_(creator), port_(port) {}

RemoteServer::~RemoteServer() {
  if (listener_) {
    evconnlistener_free(listener_);
  }
}

bool RemoteServer::Startup(std::string &error) {
  sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(port_);
  listener_ = evconnlistener_new_bind(base_, OnConnected, this,
                                      LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
                                      128, (sockaddr *)&sin, sizeof(sin));
  if (!listener_) {
    error = "bad listen on port: " + std::to_string(port_);
  }
  return !!listener_;
}

void RemoteServer::OnConnected(evconnlistener *listen, evutil_socket_t sock,
                               sockaddr *addr, int len, void *ctx) {
  ((RemoteServer *)ctx)->HandleConnected(sock);
}

void RemoteServer::HandleConnected(evutil_socket_t sock) {
  bufferevent *event =
      bufferevent_socket_new(base_, sock, BEV_OPT_CLOSE_ON_FREE);
  if (!event) {
    evutil_closesocket(sock);
    return;
  }

  (new RemoteClient(base_, dnsbase_, creator_->NewCrypto(), event))->Startup();
}

RemoteClient::RemoteClient(event_base *base, evdns_base *dnsbase,
                           Crypto *crypto, bufferevent *client)
    : base_(base), dnsbase_(dnsbase), crypto_(crypto), client_(client) {}

RemoteClient::~RemoteClient() {
  bufferevent_free(client_);
  if (target_) {
    bufferevent_free(target_);
  }
  if (target_cached_) {
    evbuffer_free(target_cached_);
  }
  crypto_->Release();
}

void RemoteClient::Startup() {
  bufferevent_setcb(client_, OnClientRead, OnClientWrite, OnClientEvent, this);
  bufferevent_enable(client_, EV_READ | EV_WRITE);
}

void RemoteClient::Cleanup(const char *reason) {
#if USE_DEBUG
  if (strstr(reason, "error")) {
    dump("cleanup: client: %d, target: %d, step: %d, %s\n",
         bufferevent_getfd(client_), target_ ? bufferevent_getfd(target_) : 0,
         step_, reason);
  }
#endif
  step_ = STEP_TERMINATE;
  delete this;
}

void RemoteClient::OnClientRead(bufferevent *bev, void *ctx) {
  RemoteClient *self = (RemoteClient *)ctx;
  evbuffer *buf = evbuffer_new();
  int ret = bufferevent_read_buffer(bev, buf);
  if (ret == 0) {
    self->HandleClientRead(buf);
  } else {
    evbuffer_free(buf);
    self->Cleanup("error: client read");
  }
}

void RemoteClient::OnClientWrite(bufferevent *bev, void *ctx) {
  ((RemoteClient *)ctx)->HandleClientEmpty();
}

void RemoteClient::OnClientEvent(bufferevent *bev, short what, void *ctx) {
  RemoteClient *self = (RemoteClient *)ctx;
  if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    self->Cleanup("client closed");
  }
}

void RemoteClient::OnTargetRead(bufferevent *bev, void *ctx) {
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

void RemoteClient::OnTargetWrite(bufferevent *bev, void *ctx) {
  ((RemoteClient *)ctx)->HandleTargetEmpty();
}

void RemoteClient::OnTargetEvent(bufferevent *bev, short what, void *ctx) {
  RemoteClient *self = (RemoteClient *)ctx;
  if (what & BEV_EVENT_CONNECTED) {
    self->HandleTargetReady();
  } else if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
    self->Cleanup("target closed");
  }
}

void RemoteClient::HandleClientRead(evbuffer *buf) {
  evbuffer *decoded = nullptr;
  int cret = crypto_->Decrypt(buf, decoded);
  if (cret == CRYPTO_NEED_NORE) {
    return;
  }

  if (cret != CRYPTO_OK) {
    Cleanup("error: client decrypt");
    return;
  }

  std::unique_ptr<evbuffer, decltype(&evbuffer_free)> decoded_clear(
      decoded, &evbuffer_free);

  if (step_ == STEP_INIT) {
    int data_len = evbuffer_get_length(decoded);
    if (data_len < 4) {
      Cleanup("error: proxy header, size");
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
        Cleanup("error: proxy header, type");
        return;
    }

    int drain_len = addr_pos + addr_len + 2;
    if (drain_len > data_len) {
      Cleanup("error: proxy header, addr");
      return;
    }

    unsigned short port =
        ntohs(*(unsigned short *)(data + addr_pos + addr_len));
    if (!port) {
      Cleanup("error: proxy header, port");
      return;
    }

    target_ = bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE);
    if (!target_) {
      Cleanup("incredible: bufferevent_socket_new");
      return;
    }

    step_ = STEP_CONNECT;
    bufferevent_setcb(target_, OnTargetRead, OnTargetWrite, OnTargetEvent,
                      this);
    bufferevent_enable(target_, EV_READ | EV_WRITE);

    char *addr = (char *)data + addr_pos;
    if (type == 3) {
      addr[addr_len] = '\0';
      bufferevent_socket_connect_hostname(target_, dnsbase_, AF_UNSPEC, addr,
                                          port);
    } else {
      sockaddr_storage sa;

      memset(&sa, 0, sizeof(sa));
      if (type == 1) {
        sockaddr_in *sin = (sockaddr_in *)&sa;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr.s_addr, addr, addr_len);
        sin->sin_port = htons(port);
      } else {
        sockaddr_in6 *sin6 = (sockaddr_in6 *)&sa;
        sin6->sin6_family = AF_INET6;
        memcpy(sin6->sin6_addr.s6_addr, addr, addr_len);
        sin6->sin6_port = htons(port);
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

    if (bufferevent_output_busy(target_)) {
      target_busy_ = true;
      bufferevent_disable(client_, EV_READ);
    }
  }
}

void RemoteClient::HandleClientEmpty() {
  if (step_ == STEP_TRANSPORT && client_busy_) {
    client_busy_ = false;
    bufferevent_enable(target_, EV_READ);
  }
}

void RemoteClient::HandleTargetReady() {
  step_ = STEP_TRANSPORT;
  if (target_cached_) {
    bufferevent_write_buffer(target_, target_cached_);
    evbuffer_free(target_cached_);
    target_cached_ = nullptr;
  }
}

void RemoteClient::HandleTargetRead(evbuffer *buf) {
  evbuffer *encoded = nullptr;
  int cret = crypto_->Encrypt(buf, encoded);
  if (cret != CRYPTO_OK) {
    Cleanup("error: target encrypt");
    return;
  }

  bufferevent_write_buffer(client_, encoded);
  evbuffer_free(encoded);

  if (bufferevent_output_busy(client_)) {
    client_busy_ = true;
    bufferevent_disable(target_, EV_READ);
  }
}

void RemoteClient::HandleTargetEmpty() {
  if (step_ == STEP_TRANSPORT && target_busy_) {
    target_busy_ = false;
    bufferevent_enable(client_, EV_READ);
  }
}
