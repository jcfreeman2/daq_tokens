
#include "daq_tokens/acquire.h"
#include <iostream>

int main(int argc, char *argv[])
{
  try {
    using daq::tokens::acquire, daq::tokens::Mode;
    std::string token =  acquire(Mode::Reuse);

    if(token == "") {
       std::cerr << "Failed to acquire token" << std::endl;
       return EXIT_FAILURE;
    }

    if(token != acquire(Mode::Reuse)) {
      std::cerr << "Failed to acquire second reusable token" << std::endl;
      return EXIT_FAILURE;
    }

    std::string token2 = acquire(Mode::Fresh);
    if(token2 == "") {
      std::cerr << "Failed to acquire second fresh token" << std::endl;
      return EXIT_FAILURE;
    }

    std::cout << token2;

    return EXIT_SUCCESS;
  } catch(daq::tokens::Issue& ex) {
    std::cerr << ex << std::endl;
  }

  return EXIT_FAILURE;
}
