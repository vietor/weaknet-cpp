#include "ProxyLocalClient.h"

ProxyLocalClient::ProxyLocalClient(bufferevent *client) : client_(client) {}

ProxyLocalClient::~ProxyLocalClient() {}

void ProxyLocalClient::Active()
{
  bufferevent_setcb(client_, OnClientRead, OnClientWrite, OnClientEvent, this);
  bufferevent_enable(client_, EV_READ | EV_WRITE);
}

void ProxyLocalClient::OnClientRead(bufferevent *bev, void *ctx) {}

void ProxyLocalClient::OnClientWrite(bufferevent *bev, void *ctx) {}

void ProxyLocalClient::OnClientEvent(bufferevent *bev, short what, void *ctx) {}
