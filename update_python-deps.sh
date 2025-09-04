#!/bin/bash

# Get the absolute path to the 'packages' directory relative to the current script
rm -rf cert-manager-lambda/packages
pip3.12 install -r cert-manager-lambda/requirements.txt --only-binary=:all: --platform manylinux2014_x86_64 -t cert-manager-lambda/packages/
