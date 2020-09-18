#!/bin/bash

rm -rf Report 2>/dev/null
rm -rf python_dep 2>/dev/null
rm -rf utility 2>/dev/null

rm -rf Analyzer/tools/server/* 2>/dev/null
mkdir Analyzer/tools/server/reports
touch Analyzer/tools/server/reports/.keep

rm -rf Analyzer/tools/others/* 2>/dev/null
mkdir Analyzer/tools/others/reports
touch Analyzer/tools/others/reports/.keep

rm -rf Evaluator/reports_to_evaluate/* 2>/dev/null
touch Evaluator/reports_to_evaluate/.keep

rm -rf Evaluator/trees_to_generate/* 2>/dev/null
touch Evaluator/trees_to_generate/.keep

echo -e '\033[1mDeletion completed successfully!\033[0m'