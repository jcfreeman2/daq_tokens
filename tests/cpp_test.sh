#!/bin/bash
token=$(./test_acquire)
./test_verify $token
