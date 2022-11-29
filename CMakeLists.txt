tdaq_package()

find_package(nlohmann_json QUIET REQUIRED HINTS ${JSONMCPP_ROOT})

tdaq_add_library(daq_tokens
  src/verify.cpp
  src/acquire.cpp
  src/common.cpp
  src/cern_sso.cpp
  gssapi-utils/gssapi.cpp
  LINK_LIBRARIES tdaq-common::ers jwt-cpp nlohmann_json::nlohmann_json Boost::headers OpenSSL::SSL UUID CURL
  )

tdaq_add_executable(token_meister
  bin/token_meister.cpp
  gssapi-utils/gssapi.cpp
  LINK_LIBRARIES jwt-cpp nlohmann_json::nlohmann_json OpenSSL::SSL Boost::headers gssapi_krb5 -static-libstdc++ -static-libgcc)

tdaq_add_executable(test_acquire
  tests/test_acquire.cpp
  NOINSTALL
  LINK_LIBRARIES daq_tokens)

tdaq_add_executable(test_verify
  tests/test_verify.cpp
  NOINSTALL
  LINK_LIBRARIES daq_tokens)

tdaq_add_executable(test_sso
  tests/test_sso.cpp
  NOINSTALL
  LINK_LIBRARIES daq_tokens)

tdaq_add_executable(test_acquire_time EXCLUDE_FROM_ALL
  tests/test_acquire_time.cpp
  NOINSTALL
  LINK_LIBRARIES daq_tokens)

tdaq_add_python_package(daq_tokens)
tdaq_add_python_package(token_meister)

tdaq_add_jar(java_daq_tokens
  jsrc/daq/tokens/*
  jsrc/daq/tokens/details/*
  jsrc/daq/tokens/internal/*
  INCLUDE_JARS Jers/ers.jar TDAQExtJars/external.jar
  OUTPUT_NAME daq_tokens
  )

tdaq_add_jar_to_repo(daq_tokens.jar
    DESCRIPTION "jar for the DAQ Tokens package")

tdaq_add_library(jdaq_tokens
  swig/JDaqTokens_wrap.cxx
  DEFINITIONS PRIVATE
    -DSWIG_JAVA_ATTACH_CURRENT_THREAD_AS_DAEMON
  OPTIONS PRIVATE
    -fno-strict-aliasing
  LINK_LIBRARIES
    daq_tokens
  INCLUDE_DIRECTORIES PRIVATE JNI)

tdaq_add_jar(daq_tokens_tests
  jsrc/tests/TestAcquire.java
  NOINSTALL
  INCLUDE_JARS daq_tokens/daq_tokens.jar Jers/ers.jar TDAQExtJars/external.jar
  )

tdaq_add_scripts(
  bin/get_daq_token
  bin/verify_daq_token
  bin/get_daq_fingerprint
  bin/token_meister_proxy
  )

tdaq_add_test(NAME start_token_meister POST_INSTALL
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/start_token_meister ${CMAKE_CURRENT_BINARY_DIR}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

tdaq_add_test(NAME tokens_python_test POST_INSTALL
  COMMAND python -m unittest discover
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/python)

tdaq_add_test(NAME cpp_acquire POST_INSTALL COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_acquire)

tdaq_add_test(NAME cpp_verify POST_INSTALL COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp_test.sh)

set(TEST_CLASSPATH "${CMAKE_CURRENT_BINARY_DIR}/daq_tokens_tests.jar:${CMAKE_INSTALL_PREFIX}/share/lib/*:${TDAQ_INST_PATH}/share/lib/*")
tdaq_add_test(NAME java_test_tokens POST_INSTALL COMMAND ${TDAQ_JAVA_HOME}/bin/java -cp ${TEST_CLASSPATH} org.junit.runner.JUnitCore tests.TestAcquire)

tdaq_add_test(NAME stop_token_meister POST_INSTALL COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/stop_token_meister WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set_tests_properties(${TDAQ_PACKAGE_NAME}_start_token_meister PROPERTIES FIXTURES_SETUP SERVER)
set_tests_properties(${TDAQ_PACKAGE_NAME}_stop_token_meister  PROPERTIES FIXTURES_CLEANUP SERVER)

set_tests_properties(
  ${TDAQ_PACKAGE_NAME}_tokens_python_test ${TDAQ_PACKAGE_NAME}_cpp_acquire ${TDAQ_PACKAGE_NAME}_cpp_verify ${TDAQ_PACKAGE_NAME}_java_test_tokens
  PROPERTIES
     ENVIRONMENT "TDAQ_TOKEN_ACQUIRE=local;TDAQ_TOKEN_PATH=/tmp/token-test/token_meister;TDAQ_TOKEN_PUBLIC_KEY_URL=file://${CMAKE_CURRENT_BINARY_DIR}/keys/public.pem;PATH=${CMAKE_CURRENT_SOURCE_DIR}/bin:${PYTHON_ROOT}/bin:$ENV{PATH};PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}/python:$ENV{PYTHONPATH};TDAQ_ERS_NO_SIGNAL_HANDLERS=1"
  )

set_tests_properties(${TDAQ_PACKAGE_NAME}_tokens_python_test  PROPERTIES FIXTURES_REQUIRED SERVER)
set_tests_properties(${TDAQ_PACKAGE_NAME}_cpp_acquire         PROPERTIES FIXTURES_REQUIRED SERVER)
set_tests_properties(${TDAQ_PACKAGE_NAME}_cpp_verify          PROPERTIES FIXTURES_REQUIRED SERVER)
set_tests_properties(${TDAQ_PACKAGE_NAME}_java_test_tokens    PROPERTIES FIXTURES_REQUIRED SERVER)
