cmake_minimum_required (VERSION 2.8)

project ("weaknet")

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_LIST_DIR}/cmake")

set(EXTERNAL_LIBRARIES "")
if (CMAKE_HOST_WIN32)
  list(APPEND EXTERNAL_LIBRARIES "-lws2_32")
else()
  list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
endif()

find_package(LibEvent REQUIRED)
if(Libevent_FOUND)
  include_directories("${LIBEVENT_INCLUDE_DIRS}")
  list(APPEND EXTERNAL_LIBRARIES "${LIBEVENT_LIBRARIES}")
endif()

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
  include_directories("${OPENSSL_INCLUDE_DIR}")
  list(APPEND EXTERNAL_LIBRARIES "${OPENSSL_LIBRARIES}")
endif()

find_package(Sodium REQUIRED)
if(Sodium_FOUND)
  include_directories("${sodium_INCLUDE_DIR}")
  list(APPEND EXTERNAL_LIBRARIES "${sodium_LIBRARIES}")
endif()

aux_source_directory(src/share SHARE_SOURCES)

aux_source_directory(src/client SERVER_SOURCES)
add_executable(weaknet-server ${SERVER_SOURCES} ${SHARE_SOURCES})
target_link_libraries(weaknet-server ${EXTERNAL_LIBRARIES})

aux_source_directory(src/client CLIENT_SOURCES)
add_executable(weaknet-client ${CLIENT_SOURCES} ${SHARE_SOURCES})
target_link_libraries(weaknet-client ${EXTERNAL_LIBRARIES})
