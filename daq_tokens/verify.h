#ifndef DAQ_TOKENS_VERIFY_H_
#define DAQ_TOKENS_VERIFY_H_

#include "daq_tokens/common.h"
#include "daq_tokens/issues.h"

#include <jwt-cpp/traits/nlohmann-json/traits.h>

#include <string_view>

namespace daq {
  namespace tokens {

    using Token     = jwt::decoded_jwt<jwt::traits::nlohmann_json>;

    /// No public key could be found.
    class NoPublicKey : public std::exception {};

    /// Verify an encoded ticket and provide an object if successful.
    ///
    /// \param encoded_token  A string containing the encoded token.
    ///
    /// \returns A decoded token.

    Token verify(std::string_view encoded_token);
  }
}

#endif // DAQ_TOKENS_VERIFY_H_
