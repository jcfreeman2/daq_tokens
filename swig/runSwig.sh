#!/bin/sh
rm ./*.cxx ./*.h
rm ../jsrc/daq/tokens/internal/*.java
swig -v -DSWIGWORDSIZE64 -outdir ../jsrc/daq/tokens/internal -package daq.tokens.internal -Wall -c++ -java ./JDaqTokens.i
