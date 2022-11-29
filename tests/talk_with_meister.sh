#!/bin/bash
#
# A pure shell script to get a token.
[ -z "${TDAQ_TOKEN_PATH}" ] && exit 1
nc -U ${TDAQ_TOKEN_PATH}
