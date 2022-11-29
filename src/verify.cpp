
#include "daq_tokens/verify.h"
#include <jwt-cpp/jwt.h>

#include <curl/curl.h>

#include <boost/process.hpp>

#include <openssl/crypto.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <mutex>
#include <shared_mutex>
#include <map>
#include <atomic>

namespace daq {

  namespace tokens {

    namespace {

      // The keysstore, a mapping from key identifier
      // to actual public key.
      class KeyStore {
      public:

        // Get a key if in store
        std::string get(const std::string& kid)
        {
          std::scoped_lock lock(m_mutex);
          auto it = m_store.find(kid);
          if(it != m_store.end()) {
            return it->second;
          }
          return "";
        }

        // Put a new key into store, calculationg its fingerprint
        void put(const std::string& key, const std::string& kid = "")
        {
          using namespace boost::process;

          std::scoped_lock lock(m_mutex);

          if(!kid.empty()) {
            m_store[kid] = key;
          } else {
            auto md5 = get_fingerprint(key, EVP_md5());
            m_store[md5] = key;
            auto sha256 = get_fingerprint(key, EVP_sha256());
            m_store[sha256] = key;
          }
        }

      private:

        std::string get_fingerprint(const std::string& key, const EVP_MD *md)
        {
          auto evp_pub = jwt::helper::load_public_key_from_string(key);

          unsigned char *data = nullptr;
          int size = i2d_PUBKEY(evp_pub.get(), &data);
          if(size < 0) { throw std::runtime_error("Cannot convert to DER"); }

          std::unique_ptr<unsigned char[]> holder(data);

          // Create digest context, CentOS 8 has newer openssl version.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
          std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
#else
          std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
#endif

          if(!ctx) { throw std::runtime_error("Cannot create MD context"); }

          if(!EVP_DigestInit(ctx.get(), md)) { throw std::runtime_error("Cannot initialize message digest"); }

          if(!EVP_DigestUpdate(ctx.get(), data, size)) { throw std::runtime_error("Cannot update message digest"); }

          std::unique_ptr<uint8_t[]> fingerprint(new uint8_t[EVP_MD_CTX_size(ctx.get())]);
          unsigned int length;

          if(!EVP_DigestFinal(ctx.get(), fingerprint.get(), &length)) {
            throw std::runtime_error("Cannot finalize message digest");
          }

          // Turn into hex
          char fp[65];
          for(decltype(length) i = 0; i < length; i++) {
            sprintf(&fp[i*2], "%02x", fingerprint[i]);
          }
          fp[length * 2] = '\0';
          return fp;
        }

        std::mutex                                   m_mutex;
        std::unordered_map<std::string, std::string> m_store;
      };

      // The only key store
      KeyStore store;

      // Global CURL initialization
      struct CurlInit {
        CurlInit()
        {
          curl_global_init(CURL_GLOBAL_ALL);
        }
        ~CurlInit()
        {
          curl_global_cleanup();
        }
      } curl_init;

      // callback function for CURL
      size_t receive_data(void *buffer, size_t size, size_t nmemb, void *userp)
      {
        std::string *key = reinterpret_cast<std::string*>(userp);
        key->append(reinterpret_cast<char *>(buffer), nmemb);
        return nmemb;
      }

      // Helper function to get public key
      std::string get_public_key(const std::string& kid)
      {

        // Check the key store first.
        std::string key = store.get(kid);

        if(!key.empty()) {
          return key;
        }

        // Key is in environment itself ?
        if(const char *pubkey = getenv("TDAQ_TOKEN_PUBLIC_KEY")) {
          store.put(pubkey);
          key = store.get(kid);
          if(!key.empty()) {
            return key;
          }
        }

        // Try to fetch latest public key from URL, CERN is default.
        std::string public_key_url = "https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/certs";

        // location should be in environment
        if(const char *url_from_env = getenv("TDAQ_TOKEN_PUBLIC_KEY_URL")) {
          public_key_url = url_from_env;
        }

        CURL *handle = curl_easy_init();
        if(!handle) {
          return "";
        }

        size_t pos = 0;
        size_t delim = public_key_url.find('|');

        while(true) {
          std::string url = public_key_url.substr(pos, delim);

          key.clear();

          CURLcode res;
          curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
          curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, receive_data);
          curl_easy_setopt(handle, CURLOPT_WRITEDATA, &key);
          res = curl_easy_perform(handle);

          if(res != CURLE_OK) {
            continue;
          }

          if(key.find("-----BEGIN") == 0) {
            store.put(key);
          } else {
            auto jwks = nlohmann::json::parse(key);
            for(auto& jwk : jwks["keys"]) {

              if(jwk["kty"] != "RSA" ||
                 jwk["alg"] != "RS256" ||
                 jwk["use"] != "sig") {
                continue;
              }

              key = jwt::helper::convert_base64_der_to_pem(jwk["x5c"][0]);
              store.put(key, jwk["kid"]);
            }
          }

          if(delim == std::string::npos) {
            break;
          }

          pos = delim + 1;
          delim = public_key_url.find('|', pos);
        }

        curl_easy_cleanup(handle);

        return store.get(kid);
      }

    } // anonymous namespace

    Token verify(std::string_view encoded_token)
    {
      try {
        Token token = jwt::decode<jwt::traits::nlohmann_json>(std::string(encoded_token));

        auto public_key = get_public_key(token.get_key_id());

        std::string issuer = "https://auth.cern.ch/auth/realms/cern";
        if(const char *env_issuer = getenv("TDAQ_TOKEN_ISSUER")) {
          issuer = env_issuer;
        }

        auto verifier = jwt::verify<jwt::default_clock, jwt::traits::nlohmann_json>(jwt::default_clock()).
          allow_algorithm(jwt::algorithm::rs256{public_key}).
          with_issuer(issuer).
          with_audience("atlas-tdaq-token").
          leeway(5);
            ;

        verifier.verify(token);
        return token;
      } catch (std::exception& ex) {
        throw CannotVerifyToken(ERS_HERE, ex);
      } catch(...) {
        throw;
      }
    }
  }
}
