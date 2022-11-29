#ifndef DAQ_TOKENS_ACQUIRE_H_
#define DAQ_TOKENS_ACQUIRE_H_

#include <string>

#include "daq_tokens/issues.h"
#include "daq_tokens/common.h"

namespace daq {
  namespace tokens {

    /// Flag to modify acquire() behaviour
    enum class Mode
      {
       // Get a new unique token
       Fresh,

       // Possibly get a cached token
       Reuse
      };

    /// Acquire a new token.
    ///
    /// \param mode If a new unique token is requested (Fresh) or a possibly cached one (Reuse)
    ///
    /// \returns A string containing the encoded ticket.
    ///
    /// \throws daq::tokens::CannotAcquireToken() in case no ticket can be acquired.
    ///
    std::string acquire(Mode mode = Mode::Reuse);
  }
}

#endif // DAQ_TOKENS_ACQUIRE_H_
