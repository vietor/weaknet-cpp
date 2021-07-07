weaknet-cpp
==============================
Replace the [weaknet-python](https://github.com/vietor/weaknet-python) with langage c/c++

# History

I was create a small **shadowsocks** server [weaknet-python](https://github.com/vietor/weaknet-python) at 2015.   
I was always used it with stream crypto algorithm **chacha20-ietf**. I found that the newest windows client was drop all stream crypto algorithm when i was buy a new Windows laptop.   
So, i need upgrade the server for my **shadowsocks** cliets. I am unhappy.

# Why

* My principle is **Simple** and **Enough**  
  I just need a server, i don't need others in the source code. I don't like split sub projects for **one** job.
  
* The libarary **libevnet** is cute, so use c/c++
