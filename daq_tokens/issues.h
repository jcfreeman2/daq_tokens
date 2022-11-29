#ifndef DAQ_TOKENS_ISSUES_H_
#define DAQ_TOKENS_ISSUES_H_

#include "ers/Issue.h"

namespace daq { 

  ERS_DECLARE_ISSUE( tokens, // namespace
                     Issue, // issue class name
                     ERS_EMPTY,
                     ERS_EMPTY
                     )

  ERS_DECLARE_ISSUE_BASE( tokens, // namespace
                          CannotAcquireToken, // issue class name
                          daq::tokens::Issue, // base class name
                          " Cannot acquire token ",
                          ERS_EMPTY,
                          ERS_EMPTY
                          )

  ERS_DECLARE_ISSUE_BASE( tokens, // namespace
                          CannotVerifyToken, // issue class name
                          daq::tokens::Issue, // base class name
                          " Cannot verify token ",
                          ERS_EMPTY,
                          ERS_EMPTY
                          )
}

#endif // DAQ_TOKENS_ISSUES_H_
