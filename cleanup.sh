#!/bin/bash

echo "# Deleting downloaded dependencies..."

rm -rf python_dep
rm -rf utility
rm -rf Analyzer/tools/others/mallodroid
rm -rf Analyzer/tools/server/testssl.sh-3.0rc5
rm -rf Analyzer/tools/server/TLS_Extended_Master_Checker
rm -rf Analyzer/tools/server/tlsfuzzer

echo "# Deletion completed successfully!"
