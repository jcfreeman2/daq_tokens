%module JDaqTokens

%{
#include "daq_tokens/common.h"
#include "daq_tokens/acquire.h"
%}

%include <typemaps.i>
%include <stl.i>
%include <std_common.i>
%include <std_string.i>
%include <various.i>
%include <enums.swg>

%javaexception("daq.tokens.AcquireTokenException") daq::tokens::acquire {
  try {
    $action
  } catch(std::exception& ex) {
    jclass clazz = jenv->FindClass("daq/tokens/AcquireTokenException");
    jenv->ThrowNew(clazz, ex.what());
    return $null;
  }
}

%include "../daq_tokens/common.h"
%include "../daq_tokens/acquire.h"
