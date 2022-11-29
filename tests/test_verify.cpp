
#include "daq_tokens/verify.h"
#include <iostream>
#include <cstdlib>

int main(int argc, char *argv[])
{
  using daq::tokens::verify;

  if(argc < 2) {
      std::cerr << argv[0] << ": expected token as first argument" << std::endl;
      return EXIT_FAILURE;
  }

  try {
    auto token = verify(argv[1]);

    std::cout << token.get_payload() << std::endl;

    auto same_token = verify(argv[1]);
    if(token.get_payload() != same_token.get_payload()) {
      return EXIT_FAILURE;
    }

    unsetenv("TDAQ_TOKEN_PUBLIC_KEY");
    setenv("TDAQ_TOKEN_PUBLIC_KEY_URL","http://not/a/valid/url", 1);

    try {
      auto token2 = verify(argv[1]);
    } catch (...) {
       return EXIT_FAILURE;
    }
  } catch (daq::tokens::Issue& ex) {
    std::cerr << ex << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
  
}
