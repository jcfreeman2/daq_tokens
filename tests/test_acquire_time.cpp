
#include "daq_tokens/acquire.h"

#include <chrono>
#include <iostream>

int main()
{
    using namespace daq::tokens;

    const int count = 1000;

    auto token = acquire(Mode::Fresh);
    auto start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < count; i++) {
       token = acquire(Mode::Fresh);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> time = end - start;
    std::cout << time.count()/count << " milliseconds/acquire" << std::endl;
}
