#!/bin/bash
set -e
exec su testrunner -c "$*"
