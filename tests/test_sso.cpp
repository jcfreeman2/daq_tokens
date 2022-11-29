
#include <string>
#include <iostream>
#include <nlohmann/json.hpp>

namespace daq {
  namespace tokens {
    std::string get_sso_token_from_kerberos(const std::string& client_id, const std::string& redirect_uri, const std::string& auth_host, const std::string& auth_realm);
  }
}

#include "daq_tokens/internal/cern_sso.h"

int main(int argc, char *argv[])
{
  std::string result = daq::tokens::get_sso_token_from_kerberos("atlas-tdaq-token", "ch.cern.atlas.tdaq:/redirect");
  std::cout << result;

  using nlohmann::json;

  json tokens = json::parse(result);
  std::cout << std::endl << daq::tokens::get_sso_token_from_refresh_token("atlas-tdaq-token", tokens["refresh_token"]);
  return (result != "");
}
