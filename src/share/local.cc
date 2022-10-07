#include "local.h"

LocalServer::LocalServer(event_base *base, evdns_base *dnsbase,
                         CryptoCreator *creator, unsigned short port,
                         const sockaddr_storage *remote_addr)
    : base_(base),
      dnsbase_(dnsbase),
      creator_(creator),
      port_(port),
      remote_addr_(remote_addr) {}

LocalServer::~LocalServer() {
  if (listener_) {
    evconnlistener_free(listener_);
  }
}

bool LocalServer::Startup(std::string &error) {
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

void LocalServer::OnConnected(evconnlistener *listen, evutil_socket_t sock,
                              sockaddr *addr, int len, void *ctx) {
  ((LocalServer *)ctx)->HandleConnected(sock);
}

void LocalServer::HandleConnected(evutil_socket_t sock) {
  bufferevent *event =
      bufferevent_socket_new(base_, sock, BEV_OPT_CLOSE_ON_FREE);
  if (!event) {
    evutil_closesocket(sock);
    return;
  }

  (new LocalClient(base_, dnsbase_, creator_->NewCrypto(), event, remote_addr_))
      ->Startup();
}

LocalClient::LocalClient(event_base *base, evdns_base *dnsbase, Crypto *crypto,
                         bufferevent *client,
                         const sockaddr_storage *remote_addr)
    : base_(base),
      dnsbase_(dnsbase),
      crypto_(crypto),
      client_(client),
      remote_addr_(remote_addr) {}

LocalClient::~LocalClient() {
  bufferevent_free(client_);
  if (target_) {
    bufferevent_free(target_);
  }
  if (target_cached_) {
    evbuffer_free(target_cached_);
  }
  crypto_->Release();
}

void LocalClient::Startup() {
  bufferevent_setcb(client_, OnClientRead, OnClientWrite, OnClientEvent, this);
  bufferevent_enable(client_, EV_READ | EV_WRITE);
}

void LocalClient::Cleanup(const char *reason) {
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

void LocalClient::ConnectTarget() {
  target_ = bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE);
  if (!target_) {
    Cleanup("incredible: bufferevent_socket_new");
    return;
  }

  step_ = STEP_CONNECT;
  bufferevent_setcb(target_, OnTargetRead, OnTargetWrite, OnTargetEvent, this);
  bufferevent_enable(target_, EV_READ | EV_WRITE);
  bufferevent_socket_connect(target_, (sockaddr *)remote_addr_,
                             sizeof(*remote_addr_));
}

void LocalClient::OnClientRead(bufferevent *bev, void *ctx) {
  LocalClient *self = (LocalClient *)ctx;
  evbuffer *buf = evbuffer_new();
  int ret = bufferevent_read_buffer(bev, buf);
  if (ret == 0) {
    self->HandleClientRead(buf);
  } else {
    evbuffer_free(buf);
    self->Cleanup("error: client read");
  }
}

void LocalClient::OnClientWrite(bufferevent *bev, void *ctx) {
  ((LocalClient *)ctx)->HandleClientEmpty();
}

void LocalClient::OnClientEvent(bufferevent *bev, short what, void *ctx) {
  LocalClient *self = (LocalClient *)ctx;
  if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    self->Cleanup("client closed");
  }
}

void LocalClient::OnTargetRead(bufferevent *bev, void *ctx) {
  LocalClient *self = (LocalClient *)ctx;
  evbuffer *buf = evbuffer_new();
  int ret = bufferevent_read_buffer(bev, buf);
  if (ret == 0)
    self->HandleTargetRead(buf);
  else {
    evbuffer_free(buf);
    self->Cleanup("error: target read");
  }
}

void LocalClient::OnTargetWrite(bufferevent *bev, void *ctx) {
  ((LocalClient *)ctx)->HandleTargetEmpty();
}

void LocalClient::OnTargetEvent(bufferevent *bev, short what, void *ctx) {
  LocalClient *self = (LocalClient *)ctx;
  if (what & BEV_EVENT_CONNECTED) {
    self->HandleTargetReady();
  } else if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
    self->Cleanup("target closed");
  }
}

void LocalClient::HandleClientRead(evbuffer *buf) {
  int data_len = evbuffer_get_length(buf);
  unsigned char *data = evbuffer_pullup(buf, data_len);

  std::unique_ptr<evbuffer, decltype(&evbuffer_free)> buf_clear(buf,
                                                                &evbuffer_free);

  if (step_ == STEP_INIT) {
    int version = data[0];
    if (version == 5) {
      if (data_len < 3) {
        Cleanup("error socks5 header, size");
        return;
      }

      step_ = STEP_WAITHDR;

      const static char socks5_resp[] = {0x05, 0x00};
      evbuffer_add(bufferevent_get_output(client_), socks5_resp,
                   sizeof(socks5_resp));
    } else if (version == 4) {
      ProcessProtocolSOCKS4(data, data_len);
    } else if (data_len > 25 && memcmp(data, "CONNECT ", 8) == 0 &&
               memcmp(data + data_len - 4, "\r\n\r\n", 4) == 0) {
      ProcessProtocolCONNECT(data, data_len);
    } else if (data_len > 25 && isupper(data[0]) && isupper(data[1]) &&
               isupper(data[2])) {
      ProcessProtocolPROXY(data, data_len);
    } else {
      Cleanup("error proxy header, block");
    }
  } else if (step_ == STEP_WAITHDR) {
    ProcessProtocolSOCKS5(data, data_len);
  } else if (step_ == STEP_CONNECT) {
    evbuffer_add_buffer(target_cached_, buf);
  } else {
    buf_clear.release();

    evbuffer *encoded = nullptr;
    if (crypto_->Encrypt(buf, encoded) != CRYPTO_OK) {
      Cleanup("error: client encrypt");
      return;
    }

    bufferevent_write_buffer(target_, encoded);
    evbuffer_free(encoded);
  }
}

void LocalClient::HandleClientEmpty() {
  if (step_ == STEP_TRANSPORT && client_busy_) {
    client_busy_ = false;
    bufferevent_enable(target_, EV_READ);
  }
}

void LocalClient::HandleTargetReady() {
  step_ = STEP_TRANSPORT;

  evbuffer *encoded = nullptr, *buf = target_cached_;
  target_cached_ = nullptr;
  if (crypto_->Encrypt(buf, encoded) != CRYPTO_OK) {
    Cleanup("error: client encrypt");
    return;
  }

  bufferevent_write_buffer(target_, encoded);
  evbuffer_free(encoded);

  if (protocol_ == PROTOCOL_SOCKS4) {
    const static char socks4_resp[] = {0x00, 0x5A, 0x00, 0x00,
                                       0x00, 0x00, 0x10, 0x10};
    evbuffer_add(bufferevent_get_output(client_), socks4_resp,
                 sizeof(socks4_resp));
  } else if (protocol_ == PROTOCOL_SOCKS5) {
    const static char socks5_resp[] = {0x05, 0x00, 0x00, 0x01, 0x00,
                                       0x00, 0x00, 0x00, 0x10, 0x10};
    evbuffer_add(bufferevent_get_output(client_), socks5_resp,
                 sizeof(socks5_resp));
  } else if (protocol_ == PROTOCOL_CONNECT) {
    const static char http_resp[] =
        "HTTP/1.1 200 Connection Established\r\n\r\n";
    evbuffer_add(bufferevent_get_output(client_), http_resp,
                 sizeof(http_resp) - 1);
  }
}

void LocalClient::HandleTargetRead(evbuffer *buf) {
  evbuffer *decoded = nullptr;
  int cret = crypto_->Decrypt(buf, decoded);
  if (cret == CRYPTO_NEED_NORE) {
    return;
  }
  if (cret != CRYPTO_OK) {
    Cleanup("error: target decrypt");
    return;
  }

  bufferevent_write_buffer(client_, decoded);
  evbuffer_free(decoded);

  if (bufferevent_output_busy(client_)) {
    client_busy_ = true;
    bufferevent_disable(target_, EV_READ);
  }
}

void LocalClient::HandleTargetEmpty() {
  if (step_ == STEP_TRANSPORT && target_busy_) {
    target_busy_ = false;
    bufferevent_enable(client_, EV_READ);
  }
}

void LocalClient::ProcessProtocolSOCKS4(unsigned char *data, int data_len) {
  if (data_len < 9 || data[data_len - 1] != 0x00) {
    Cleanup("error socks4 header, size");
    return;
  }

  if (data[1] != 0x01) {
    Cleanup("error socks4 command");
    return;
  }

  protocol_ = PROTOCOL_SOCKS4;
  target_cached_ = evbuffer_new();

  unsigned char block[2];
  if (data[4] != 0 || data[5] != 0 || data[6] != 0) {
    block[0] = 0x01;
    evbuffer_add(target_cached_, block, 1);
    evbuffer_add(target_cached_, data + 4, 4);
    evbuffer_add(target_cached_, data + 2, 2);
  } else {
    unsigned char *ptr = (unsigned char *)memchr(data + 7, 0, data_len - 7);
    if (!ptr) {
      Cleanup("error socks4 userid");
      return;
    }

    int domain = (ptr - data) + 1;
    ptr = (unsigned char *)memchr(data + domain, 0, data_len - domain);
    if (!ptr) {
      Cleanup("error socks4a domain");
      return;
    }

    int domain_len = strlen((char *)data + domain);
    if (domain_len > 255) {
      Cleanup("error socks4a domain, size");
      return;
    }

    block[0] = 0x03;
    block[1] = (unsigned char)domain_len;
    evbuffer_add(target_cached_, block, sizeof(block));
    evbuffer_add(target_cached_, data + domain, domain_len);
    evbuffer_add(target_cached_, data + 2, 2);
  }

  ConnectTarget();
}

void LocalClient::ProcessProtocolSOCKS5(unsigned char *data, int data_len) {
  if (data_len < 7 || data[0] != 0x05) {
    Cleanup("error socks5 header, size");
    return;
  }

  if (data[1] != 0x01) {
    Cleanup("error socks5 command");
    return;
  }

  int atyp = data[3], rear = -1;
  switch (atyp) {
    case 0x01:
      rear = 10;
      break;
    case 0x03:
      rear = 7 + data[4];
      break;
    case 0x04:
      rear = 22;
      break;
    default:
      break;
  }
  if (rear < 1 || rear > data_len) {
    Cleanup("error socks5 address");
    return;
  }

  protocol_ = PROTOCOL_SOCKS5;
  target_cached_ = evbuffer_new();
  evbuffer_add(target_cached_, data + 3, data_len - 3);

  ConnectTarget();
}

void LocalClient::ProcessProtocolCONNECT(unsigned char *data, int data_len) {
  int begin = 8, end = begin + 1;
  while (end < data_len && data[end] != ' ') ++end;
  if (end + 10 > data_len || memcmp(data + end, " HTTP/1.", 8)) {
    Cleanup("error connect header, format");
    return;
  }

  int sep = end;
  while (sep > begin && data[sep] != ':') --sep;
  if (sep <= begin || sep == end - 1) {
    Cleanup("error connect header, address");
    return;
  }

  data[end] = 0;
  data[sep++] = 0;

  int port = atoi((char *)data + sep);
  int domain_len = strlen((char *)data + begin);
  if (domain_len > 255 || port < 1 || port > 65535) {
    Cleanup("error connect header, address");
    return;
  }

  unsigned char block1[2], block2[2];
  block1[0] = 0x03;
  block1[1] = (unsigned char)domain_len;
  *((unsigned short *)block2) = htons(port);

  protocol_ = PROTOCOL_CONNECT;
  target_cached_ = evbuffer_new();
  evbuffer_add(target_cached_, block1, sizeof(block1));
  evbuffer_add(target_cached_, data + begin, domain_len);
  evbuffer_add(target_cached_, block2, sizeof(block2));

  ConnectTarget();
}

void LocalClient::ProcessProtocolPROXY(unsigned char *data, int data_len) {
  int sep = 0, http_flag = 0, url_start = 0, address_start = 0, path_start = 0;
  unsigned char *ptr = (unsigned char *)memchr(data, ' ', data_len);
  if (ptr) {
    url_start = (ptr - data) + 1;
    if (memcmp(data + url_start, "http", 4) == 0 && data_len - url_start > 25) {
      http_flag = 1;
      sep = url_start + 4;
      if (data[url_start + 5] == 's') {
        ++sep;
        http_flag = 2;
      }
    }
    if (http_flag) {
      if (memcmp(data + sep, "://", 3)) {
        http_flag = 0;
      } else {
        address_start = sep + 3;
      }
    }
    if (http_flag) {
      ptr = (unsigned char *)memchr(data + address_start, '/',
                                    data_len - address_start);
      if (!ptr) {
        http_flag = 0;
      } else {
        path_start = ptr - data;
        if (path_start - address_start < 3) {
          http_flag = 0;
        }
      }
    }
  }

  if (!http_flag) {
    Cleanup("error proxy header, protocol");
    return;
  }

  int port = http_flag == 1 ? 80 : 443;
  int domain_len = path_start - address_start;
  ptr = (unsigned char *)memchr(data + address_start, ':',
                                path_start - address_start);
  if (ptr) {
    *ptr = 0;
    data[path_start] = 0;
    port = atoi((char *)ptr + 1);
    data[path_start] = '/';

    domain_len = ptr - data - address_start;
  }

  unsigned char block1[2], block2[2];
  block1[0] = 0x03;
  block1[1] = (unsigned char)domain_len;
  *((unsigned short *)block2) = htons(port);

  protocol_ = PROTOCOL_PROXY;
  target_cached_ = evbuffer_new();
  evbuffer_add(target_cached_, block1, sizeof(block1));
  evbuffer_add(target_cached_, data + address_start, domain_len);
  evbuffer_add(target_cached_, block2, sizeof(block2));
  evbuffer_add(target_cached_, data, url_start);
  evbuffer_add(target_cached_, data + path_start, data_len - path_start);

  ConnectTarget();
}
