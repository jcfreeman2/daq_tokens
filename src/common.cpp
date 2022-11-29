
#include "daq_tokens/common.h"
#include <string.h>
#include <cstdlib>

namespace daq {
  namespace tokens {

    bool enabled()
    {
      if(const char *val = getenv("TDAQ_TOKEN_CHECK")) {
        return strcmp(val, "1") == 0;
      }
      return false;
    }
  }
}
