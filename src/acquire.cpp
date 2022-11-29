
#include "daq_tokens/acquire.h"
#include "daq_tokens/internal/cern_sso.h"
#include "gssapi-utils/gssapi.h"

#include <nlohmann/json.hpp>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <jwt-cpp/jwt.h>

#include <boost/process.hpp>
#include <boost/algorithm/string.hpp>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <mutex>

#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>

namespace daq {
  namespace tokens {

    namespace {

      std::mutex  mutex;

      std::string last_token;
      std::chrono::system_clock::time_point last_token_time;

      nlohmann::json last_sso_token;
      std::chrono::system_clock::time_point last_sso_token_time;
    }

    std::string acquire(Mode mode)
    {
      std::scoped_lock lock(mutex);

      try {
        // Check if we can re-use the last token
        if(mode == Mode::Reuse) {
          if(!last_token.empty() && (std::chrono::system_clock::now() < last_token_time + std::chrono::seconds(600))) {
            return last_token;
          }
        }

        std::vector<std::string> methods{"env", "local", "kerberos"};

        if(const char *method_var = getenv("TDAQ_TOKEN_ACQUIRE")) {
          methods.clear();
          boost::algorithm::split(methods, method_var,  boost::algorithm::is_space());
        }

        for(auto& method : methods) {

          if(method == "env") {
            std::string token = get_sso_token_from_environment();
            if(token.empty()) {
              continue;
            }

            try {
              auto decoded = jwt::decode<jwt::traits::nlohmann_json>(token);
              if (decoded.get_expires_at() - std::chrono::seconds(600) < std::chrono::system_clock::now()) {
                continue;
              }
            } catch(...) {
              continue;
            }

            last_token = token;
            last_token_time = std::chrono::system_clock::now();

            return token;
          }

          if(method == "local") {

            // Check if we should use local Unix socket
            if(const char *path_var = getenv("TDAQ_TOKEN_PATH")) {

              std::vector<std::string> paths;
              boost::algorithm::split(paths, path_var, [](char c) { return c == ':'; });
              char buffer[32000];
              int  n = 0;

              for(auto& path : paths) {
                buffer[0] = '\0';
                n = 0;

                struct sockaddr_un addr { AF_UNIX };
                strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

                int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
                if(fd < 0) {
                  throw std::runtime_error("Cannot create token socket");
                }

                int retries = 2;
                while(retries-- > 0 && connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                  using namespace std::chrono_literals;
                  if(retries > 0) {
                    std::this_thread::sleep_for(50ms);
                  }
                }

                // if we can't connect, try next method
                if(retries <= 0) {
                  close(fd);
                  continue;
                }

                // if we can connect, any follow up error is an exception
                n = read(fd, buffer, sizeof(buffer) - 1);
                if(n < 0) {
                  close(fd);
                  throw std::runtime_error("Cannot read from token socket");
                }
                buffer[n] = '\0';
                close(fd);

                if(buffer[0] == '\0') {
                  throw std::runtime_error("Received no token from socket");
                }

                break;
              }

              if(mode == Mode::Reuse && n > 0) {
                last_token = buffer;
                last_token_time = std::chrono::system_clock::now();
              }
              return buffer;
            }
          }

          if(method == "gssapi") {
            // default gssapi server host
            std::string hostname{"vm-atdaq-token.cern.ch"};
            if(const char *h = getenv("TDAQ_TOKEN_GSSAPI_HOST")) {
              hostname = h;
            }

            // default port
            std::string port{"8991"};
            if(const char *p = getenv("TDAQ_TOKEN_GSSAPI_PORT")) {
              port = p;
            }

            addrinfo hints{AI_NUMERICSERV, AF_INET, SOCK_STREAM, 0};
            addrinfo *result;

            if(getaddrinfo(hostname.c_str(), port.c_str(), &hints, &result) != 0) {
              continue;
            }

            int client_socket = -1;
            for(addrinfo *ai = result; ai != 0; ai = ai->ai_next) {
              client_socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
              if(client_socket >= 0) {
                if(connect(client_socket, ai->ai_addr, ai->ai_addrlen) != 0) {
                  close(client_socket);
                  continue;
                }
                break;
              }
            }

            freeaddrinfo(result);

            if(client_socket == -1) {
              continue;
            }

            try {
              gssapi_utils::context ctx{client_socket, "atdaqjwt@" + hostname};
              size_t length;
              auto buffer = ctx.recv(length);
              if(!buffer) {
                continue;
              }

              std::string result{buffer.get(), length};
              if (mode == Mode::Reuse) {
                last_token = result;
                last_token_time = std::chrono::system_clock::now();
              }
              return result;
            } catch (std::exception& ex) {
            }
            continue;
          }

          // SSO based token methods

          std::string raw_result;

          // if we have a refresh token, try to use that.
          if(!last_sso_token.is_null() &&
             (last_sso_token_time + std::chrono::seconds(last_sso_token["refresh_expires_in"]) > std::chrono::system_clock::now())) {
            raw_result = get_sso_token_from_refresh_token("atlas-tdaq-token", last_sso_token["refresh_token"]);
          }

          if(raw_result.empty()) {

            if(method == "kerberos") {
              raw_result = get_sso_token_from_kerberos("atlas-tdaq-token", "ch.cern.atlas.tdaq:/redirect");
            }

            if(method == "browser") {
              raw_result = get_sso_token_from_browser("atlas-tdaq-token");
            }

            if(method == "password") {
              // TODO
            }
          }

          if(raw_result.empty()) {
            // try next method
            continue;
          }

          // Here we  got a new token
          last_sso_token  = nlohmann::json::parse(raw_result);
          last_token_time = std::chrono::system_clock::now();

          if(mode == Mode::Reuse) {
            last_token = last_sso_token["access_token"];
            last_token_time = std::chrono::system_clock::now();
          }
          return last_sso_token["access_token"];
        }

        // out of methods to try
        throw std::runtime_error("Could not acquire token");

      } catch (std::exception& ex) {
        throw CannotAcquireToken(ERS_HERE, ex);
      } catch(...) {
        // we don't expect any non-std derived exceptions
        throw;
      }
    }
  }
}

