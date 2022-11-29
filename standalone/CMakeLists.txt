cmake_minimum_required(VERSION 3.14)

project(TokenMeister)

include(GNUInstallDirs)
include(FetchContent)

FetchContent_Declare(json
  URL https://github.com/nlohmann/json/archive/refs/tags/v3.11.2.tar.gz
  )

FetchContent_Declare(jwt-cpp
  URL https://github.com/Thalhammer/jwt-cpp/archive/refs/tags/v0.6.0.tar.gz
  )

set(JWT_BUILD_EXAMPLES OFF CACHE BOOL "Override jwt build options")

FetchContent_GetProperties(json)
if(NOT json_POPULATED)
  FetchContent_Populate(json)
  add_subdirectory(${json_SOURCE_DIR} ${json_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

FetchContent_GetProperties(jwt-cpp)
if(NOT jwt-cpp_POPULATED)
  FetchContent_Populate(jwt-cpp)
  add_subdirectory(${jwt-cpp_SOURCE_DIR} ${jwt-cpp_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# FetchContent_MakeAvailable(json jwt-cpp)

add_subdirectory(boost-cmake)

find_package(OpenSSL REQUIRED Crypto)

add_executable(token_meister ../bin/token_meister.cpp ../gssapi-utils/gssapi.cpp)
target_link_libraries(token_meister jwt-cpp nlohmann_json Boost::boost OpenSSL::Crypto gssapi_krb5 -static-libstdc++ -static-libgcc)
target_include_directories(token_meister PRIVATE ..)

install(TARGETS token_meister RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES 
  ../etc/systemd/system/tdaq_token.socket 
  ../etc/systemd/system/tdaq_token.service
  ../etc/systemd/system/tdaq_token_gssapi.socket
  ../etc/systemd/system/tdaq_token_gssapi.service
  DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/systemd/system)
