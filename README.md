weaknet-cpp
==============================
Replace the [weaknet-python](https://github.com/vietor/weaknet-python) with langage c/c++

# History

I was create a small **shadowsocks** server [weaknet-python](https://github.com/vietor/weaknet-python) at 2015.   
I was always used it with stream crypto algorithm **chacha20-ietf**. I found that the newest windows client was drop all stream crypto algorithm when i was buy a new Windows laptop at 2021.   
So, i need upgrade the server for my **shadowsocks** cliets. I am unhappy.

# Why

* My principle is **Simple** and **Enough**  
  I just need a server, i don't need others in the source code. I don't like split sub projects for **one** job.
  
* The library **libevnet** is cute, so use c/c++

# Usage

## weaknet-server

```
Usage: weaknet-server <options>
Options:
 -p or --port <port>, range 1-65535
 -m or --algorithm <algorithm>, support list:
    chcha20, chch20-ietf,
    chacha20-ietf-poly1305,
    xchacha20-ietf-poly1305
 -s or --password <password>
 - or --help
```

## weaknet-client

```
Usage: weaknet-client <options>
Options:
 -p or --port <port>, range 1-65535
 -m or --algorithm <algorithm>, support list:
    chcha20, chch20-ietf,
    chacha20-ietf-poly1305,
    xchacha20-ietf-poly1305
 -s or --password <password>
 -R or --remote-addr <ip:port>
 -h or --help
```
