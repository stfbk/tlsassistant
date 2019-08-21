#!/bin/bash

echo "# Deleting downloaded dependencies..."

rm -rf python_dep 2>/dev/null
rm -rf utility 2>/dev/null
rm -rf Analyzer/tools/others/mallodroid 2>/dev/null
rm -rf Analyzer/tools/server/testssl.sh-3.0rc5 2>/dev/null
rm -rf Analyzer/tools/server/TLS_Extended_Master_Checker 2>/dev/null
rm -rf Analyzer/tools/server/tlsfuzzer 2>/dev/null

echo "# Deletion completed successfully!"
