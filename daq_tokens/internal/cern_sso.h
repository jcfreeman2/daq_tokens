#ifndef DAQ_TOKENS_CERN_SSP_H_
#define DAQ_TOKENS_CERN_SSP_H_

#include <string>

namespace daq {
  namespace tokens {

    ///
    /// Acquire a token from CERN server using kerberos.
    ///
    /// Returns a JSON formatted string containing the access and refresh token
    ///
    std::string get_sso_token_from_kerberos(const std::string& client_id,
                                            const std::string& redirect_uri,
                                            const std::string& auth_host = "auth.cern.ch",
                                            const std::string& auth_realm = "cern");
    ///
    /// Refresh a token.
    ///
    /// Returns a JSON formatted string containing the access and refresh token
    ///
    std::string get_sso_token_from_refresh_token(const std::string& client_id,
                                                 const std::string& refresh_token,
                                                 const std::string& auth_host = "auth.cern.ch",
                                                 const std::string& auth_realm = "cern");

    ///
    /// Acquire a token with the help of the user's browser.
    ///
    /// Returns a JSON formatted string containing the access and refresh token
    ///
    std::string get_sso_token_from_browser(const std::string& client_id,
					   const std::string& redirect_uri = "http://localhost",
					   const std::string& auth_host = "auth.cern.ch",
					   const std::string& auth_realm = "cern");

    // Seriously, don't use this.
    std::string get_sso_token_from_password(const std::string& client_id,
                                            const std::string& redirect_uri,
                                            const std::string& username,
                                            const std::string& password,
                                            const std::string& auth_host = "auth.cern.ch",
                                            const std::string& auth_realm = "cern");
    ///
    /// Acquire token from environment, following WLCG proposal
    ///
    std::string get_sso_token_from_environment();
  }
}

#endif // DAQ_TOKENS_CERN_SSP_H_
