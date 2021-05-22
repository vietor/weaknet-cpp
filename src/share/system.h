#ifndef SYSTEM_H_
#define SYSTEM_H_

#if defined(__linux) || defined(__linux__) || defined(linux)
#define SYS_LINUX
#elif defined(__APPLE__)
#define SYS_MACOS
#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32) || defined(_WIN64)
#define SYS_WINDOWS
#endif

#ifdef SYS_WINDOWS
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

#endif
