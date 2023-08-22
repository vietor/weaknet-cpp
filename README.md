weaknet-cpp
==============================
A simple and enough **Shadowsocks** Implementation.

# History

I was create a small **shadowsocks** server [weaknet-python](https://github.com/vietor/weaknet-python) at 2015.   
I was always used it with stream crypto algorithm **chacha20-ietf**. I found that the newest windows client was drop all stream crypto algorithm when i was buy a new Windows laptop at 2021.   
So, i need upgrade the server for my **shadowsocks** clients. I am unhappy.

# Why

* My principle is **Simple** and **Enough**  
  I just need a server, i don't need others in the source code. I don't like split sub projects for **one** job.
  
* The library **libevent** is cute, so use c/c++

# Build

Depends on **libevent** **openssl** **sodium**.

```
cmake -DCMAKE_BUILD_TYPE=Release .
```

# Usage

## weaknet-server

```
Usage: weaknet-server [command-line-file] [options]
Options:
 -p or --port <port>, range 1-65535
 -m or --algorithm <algorithm>, support list:
    chacha20, chacha20-ietf,
    chacha20-ietf-poly1305,
    xchacha20-ietf-poly1305
 -s or --password <password>
 -v or --version
 -h or --help
```

## weaknet-client

Support *socks4* *socks4a* *socks5* *http-connect* *http-proxy* protocol.

```
Usage: weaknet-client [command-line-file] [options]
Options:
 -p or --port <port>, range 1-65535
 -m or --algorithm <algorithm>, support list:
    chacha20, chacha20-ietf,
    chacha20-ietf-poly1305,
    xchacha20-ietf-poly1305
 -s or --password <password>
 -R or --remote-addr <ip:port>
 -v or --version
 -h or --help
```
