
#include "daq_tokens/internal/cern_sso.h"

#include "ers/ers.h"

#include <curl/curl.h>

#include <cstdlib>
#include <mutex>
#include <map>
#include <algorithm>
#include <string.h>
#include <memory>
#include <fstream>

#include <unistd.h>
#include <netinet/in.h>

namespace daq {

  namespace tokens {

    namespace {

      // callback function for CURL
      size_t receive_data(void *buffer, size_t size, size_t nmemb, void *userp)
      {
        std::string *key = reinterpret_cast<std::string*>(userp);
        key->append(reinterpret_cast<char *>(buffer), nmemb * size);
        return nmemb * size;
      }
      
      // callback function for CURL, ignore all
      size_t ignore_data(void *buffer, size_t size, size_t nmemb, void *userp)
      {
        return nmemb * size;
      }

      // Send string to socket.
      int send_text(int s, const char *msg)
      {
	return send(s, msg, strlen(msg), 0);
      }

      std::string auth_success_url{getenv("TDAQ_TOKEN_AUTH_SUCCESS") ? getenv("TDAQ_TOKEN_AUTH_SUCCESS") : "https://atlas-tdaq-sw.web.cern.ch/atlas-tdaq-sw/auth/success.html"};
      std::string auth_failure_url{getenv("TDAQ_TOKEN_AUTH_FAILURE") ? getenv("TDAQ_TOKEN_AUTH_FAILURE") : "https://atlas-tdaq-sw.web.cern.ch/atlas-tdaq-sw/auth/failure.html"};

    } // anonymous namespace

    /// Refresh an existing token, get new access and refresh token
    std::string get_sso_token_from_refresh_token(const std::string& client_id,
                                                 const std::string& refresh_token,
                                                 const std::string& auth_host,
                                                 const std::string& auth_realm)
    {
      std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handler(curl_easy_init(), curl_easy_cleanup);
      CURL *handle = handler.get();
      if(handle == nullptr) return "";

      std::string url{"https://"};
      url += auth_host + "/auth/realms/" + auth_realm + "/protocol/openid-connect/token";
      curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
      
      std::string post_data{"grant_type=refresh_token"};      
      post_data += "&client_id=" + client_id;
      post_data += "&refresh_token=" + refresh_token;
      curl_easy_setopt(handle, CURLOPT_POSTFIELDS, post_data.c_str());

      std::string result;
      curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, receive_data);
      curl_easy_setopt(handle, CURLOPT_WRITEDATA, &result);

      CURLcode res = curl_easy_perform(handle);
      if(res != CURLE_OK) {
        return "";
      }
      return result;
    }

    // Get brand new token via kerberos.
    std::string get_sso_token_from_kerberos(const std::string& client_id, const std::string& redirect_uri, const std::string& auth_host, const std::string& auth_realm)
    {
      std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handler(curl_easy_init(), curl_easy_cleanup);
      CURL *handle = handler.get();

      if(handle == nullptr) {
        return "";
      }

      curl_easy_setopt(handle, CURLOPT_COOKIEFILE, "");

      // Get random printable string
      std::string state(40, '\0');
      std::generate_n( state.begin(), 40,
                       []() -> char
                       {
                         const char charset[] =
                           "0123456789"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz";
                         const size_t max_index = (sizeof(charset) - 1);
                         return charset[ rand() % max_index ];
                       });

      // The keycloak login page
      std::string login_page{"https://"};
      login_page += auth_host + "/auth/realms/" + auth_realm + "/protocol/openid-connect/auth?";
      login_page += "client_id=" + client_id + "&response_type=code&state=" + state + "&redirect_uri=" + redirect_uri;

      CURLcode res;
      std::string page;
      
      curl_easy_setopt(handle, CURLOPT_URL, login_page.c_str());
      curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, receive_data);
      curl_easy_setopt(handle, CURLOPT_WRITEDATA, &page);
      curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
      res = curl_easy_perform(handle);
      if(res != CURLE_OK) {
        return "";
      }

      // hack to avoid parsing the full HTML page
      // 1. find 'id="social-kerberos"' in page
      // 2. rfind '<a' starting from 1.
      // 3. find 'href="' starting from 2
      size_t idx = page.find(" id=\"social-kerberos\"");
      if(idx == std::string::npos) return "";

      idx = page.rfind("<a ", idx);
      if(idx == std::string::npos) return "";

      idx = page.find(" href=\"", idx);
      if(idx == std::string::npos) return "";

      size_t end_idx = page.find("\"", idx + 8);
      if(end_idx == std::string::npos) return "";

      std::string href{page.substr(idx + 8, end_idx - idx - 8)};

      idx = 0;
      do {
        if((idx = href.find("&amp;", idx)) != std::string::npos) {
          href.replace(idx, 5, "&");
        }
      } while(idx != std::string::npos);
        
      std::string url{"https://"};
      url += auth_host + '/' + href;

      // Go to kerberos handling page
      curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
      curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, ignore_data);
      curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
      res = curl_easy_perform(handle);
      if(res != CURLE_OK) {
        return "";
      }

      long response_code;
      char *last_url = nullptr;
      
      curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code);
      curl_easy_getinfo(handle, CURLINFO_REDIRECT_URL, &last_url);
      
      url = last_url;

      curl_easy_setopt(handle, CURLOPT_USERNAME, "");
      curl_easy_setopt(handle, CURLOPT_PASSWORD, "");
      curl_easy_setopt(handle, CURLOPT_HTTPAUTH, CURLAUTH_GSSNEGOTIATE);

      curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
      curl_easy_setopt(handle, CURLOPT_URL, url.c_str());

      res = curl_easy_perform(handle);
      if(res != CURLE_OK) {
        return "";
      }

      curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code);
      curl_easy_getinfo(handle, CURLINFO_REDIRECT_URL, &last_url);
      url = last_url;
      
      while((response_code == 302) &&
            (url.find(redirect_uri) == std::string::npos)) {
        // std::cout << "last [" << response_code << "] redirect URL = " << url << std::endl;
        curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
        res = curl_easy_perform(handle);
        if(res != CURLE_OK) {
          return ""; 
        }
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_getinfo(handle, CURLINFO_REDIRECT_URL, &last_url);
        url = last_url;
      }

      // std::cout << "last [" << response_code << "] redirect URL = " << url << std::endl;

      size_t state_idx = url.find("state=");
      if(state_idx == std::string::npos) {
        return "";
      }

      size_t state_end = url.find("&", state_idx);
      std::string state_received = url.substr(state_idx + 6, state_end - state_idx - 6);
      if (state_received != state) {
        return "";
      }
      
      size_t code_idx  = url.find("code=");
      if(code_idx == std::string::npos) {
        return "";
      }
      size_t code_end = url.find("&", code_idx);
      std::string code = url.substr(code_idx + 5, code_end - code_idx - 5);

      std::string token_endpoint{"https://"};
      token_endpoint += auth_host + "/auth/realms/" + auth_realm + "/protocol/openid-connect/token";
      curl_easy_setopt(handle, CURLOPT_URL, token_endpoint.c_str());

      std::string post_data{"grant_type=authorization_code"};
      post_data += "&client_id=" + client_id;
      post_data += "&code=" + code;
      post_data += "&redirect_uri=" + redirect_uri;
      curl_easy_setopt(handle, CURLOPT_POSTFIELDS, post_data.c_str());

      page.clear();
      curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, receive_data);
      curl_easy_setopt(handle, CURLOPT_WRITEDATA, &page);
      curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);

      res = curl_easy_perform(handle);
      if(res != CURLE_OK) {
        return "";
      }
      return page;
    }

    std::string get_sso_token_from_browser(const std::string& client_id,
					   const std::string& redirect_uri,
					   const std::string& auth_host,
					   const std::string& auth_realm)
    {
      int server = socket(PF_INET6, SOCK_STREAM, 0);
      if(server < 0) {
	return "";
      }

      
      sockaddr_in6 addr;
      memset(&addr, 0, sizeof(addr));
      addr.sin6_family = AF_INET6;
      addr.sin6_addr = IN6ADDR_LOOPBACK_INIT ;
      if(bind(server, (struct sockaddr *) &addr, sizeof(sockaddr_in6)) < 0) {
	close(server);
	return "";
      }
      
      if(listen(server, 1) < 0) {
	close(server);
	return "";
      }

      socklen_t sock_length = sizeof(addr);
      getsockname(server, (sockaddr *)&addr, &sock_length);
      
      unsigned short port = ntohs(addr.sin6_port);

      // Get random printable string
      std::string random_state(40, '\0');
      std::generate_n( random_state.begin(), 40,
                       []() -> char
                       {
                         const char charset[] =
                           "0123456789"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz";
                         const size_t max_index = (sizeof(charset) - 1);
                         return charset[ rand() % max_index ];
                       });
      
      
      std::string authz_url{"https://"};
      authz_url += auth_host + "/auth/realms/" + auth_realm +
	"/protocol/openid-connect/auth?response_type=code&client_id=" + client_id +
	"&state=" + random_state + "&redirect_uri=" + redirect_uri + ":" + std::to_string(port);

      int err = system(("xdg-open '" + authz_url + "' &").c_str());
      if(err != 0) {
	close(server);
	return "";
      }

      int conn = accept(server, nullptr, 0);
      close(server);
      if(conn < 0) {
	return "";
      }

      char buffer[1024];
      int count = read(conn, buffer, sizeof(buffer) -1);
      if (count < 0) {
	close(conn);
	return "";
      }

      buffer[count] = '\0';

      std::string_view buf(buffer);

      auto pos = buf.find('\n');
      buf.remove_suffix(buf.size() - pos);

      if(buf.find("GET ") != 0) {
	return "";
      }
      buf.remove_prefix(4);
      pos = buf.rfind(" HTTP/");
      if(pos == std::string_view::npos) {
	close(conn);
	return "";
      }

      buf.remove_suffix(buf.size() - pos);

      if((pos = buf.find("state=")) == std::string_view::npos) {
	close(conn);
	return "";
      }

      auto endpos = buf.find("&", pos);
      if(endpos == std::string_view::npos)
	endpos = buf.size();

      if(random_state != buf.substr(pos + 6, endpos - pos - 6)) {
	ERS_LOG("Invalid state returned");
	send_text(conn, "HTTP/1.1 302 Redirect\r\nLocation: https://atlas-tdaq-sw.web.cern.ch/atlas-tdaq-sw/auth/failure.html\r\n\r\n");
	close(conn);
	return "";
      }

      if((pos = buf.find("code=")) == std::string_view::npos) {
	ERS_LOG("No code  returned");
	send_text(conn, "HTTP/1.1 302 Redirect\r\nLocation: https://atlas-tdaq-sw.web.cern.ch/atlas-tdaq-sw/auth/failure.html\r\n\r\n");
	close(conn);
	return "";
      }

      endpos = buf.find("&", pos);
      if(endpos == std::string_view::npos)
	endpos = buf.size();

      std::string code = std::string(buf.substr(pos + 5, endpos - pos - 5));
      send_text(conn, "HTTP/1.1 302 Redirect\r\nLocation: https://atlas-tdaq-sw.web.cern.ch/atlas-tdaq-sw/auth/success.html\r\n\r\n");
      close(conn);

      std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handler(curl_easy_init(), curl_easy_cleanup);
      CURL *handle = handler.get();

      if(handle == nullptr) {
        return "";
      }

      std::string token_endpoint{"https://"};
      token_endpoint += auth_host + "/auth/realms/" + auth_realm + "/protocol/openid-connect/token";
      curl_easy_setopt(handle, CURLOPT_URL, token_endpoint.c_str());

      std::string post_data{"grant_type=authorization_code"};
      post_data += "&client_id=" + client_id;
      post_data += "&code=" + code;
      post_data += "&redirect_uri=" + redirect_uri + ":" + std::to_string(port);
      curl_easy_setopt(handle, CURLOPT_POSTFIELDS, post_data.c_str());

      std::string page;
      curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, receive_data);
      curl_easy_setopt(handle, CURLOPT_WRITEDATA, &page);
      curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);

      auto res = curl_easy_perform(handle);
      if(res != CURLE_OK) {
        return "";
      }
      return page;      
    }
    

    std::string get_sso_token_from_password(const std::string& client_id,
                                            const std::string& redirect_uri,
                                            const std::string& username,
                                            const std::string& password,
                                            const std::string& auth_host,
                                            const std::string& auth_realm)
    {
      return "";
    }

    std::string get_sso_token_from_environment()
    {
      if(const char *token = getenv("BEARER_TOKEN")) {
	return token;
      }

      std::string file_name;
      if(const char *filename = getenv("BEARER_TOKEN_FILE")) {
	file_name = filename;
      } else {
	uid_t uid = geteuid();
	if(const char *runtime = getenv("XDG_RUNTIME_DIR")) {
	  file_name = runtime;
	  file_name += "/bt_u";
	} else {
	  file_name = "/tmp/bt_u";
	}
	file_name += std::to_string(uid);
	file_name += "-atlas-tdaq";
      }

      std::ifstream stream(file_name.c_str());
      std::string token;
      getline(stream, token);
      if(stream.good()) {
	return token;
      }
      return "";
    }
  }
}
