#!/bin/bash

#env
root_folder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
tools=$root_folder/tools/others #other tools path (starting from the project root)
report=$tools/reports #other scans' report path (starting from the project root)
evaluatorReports=$root_folder/../Evaluator/reports_to_evaluate
python=$root_folder/../python_dep/bin/python

##functions definition
function s_echo {
    callingFunction="${FUNCNAME[1]}"
    echo "[$callingFunction] $1"
}

function mallodroid {
    version="#17ab2eb" #version (does not have a real versioning, using the commit identifier)
    mallodroid_folder=$tools/mallodroid #location
    args="-x -f" #to show, in order: protocols, preferences, header, vulnerabilities (see documentation)

    cd $mallodroid_folder
    s_echo "version: $version"
    s_echo "Analyzing..."
    $python $mallodroid_folder/mallodroid.py $args $1 | aha -t ${FUNCNAME[0]} > $report/mallodroid_report.html
    s_echo "Report generated successfully!"
    echo
    cd $root_folder
}

#cleanup
rm -r $report/* 2>/dev/null #removing old reports (suppressing the warnings)

echo
echo "---Begin apk scan---"
echo "Target: $(basename -- "$1")"
echo

#scripts call
mallodroid $1

#provide the reports to the Evaluator
for file in $report/*; do #for each report available

    name=${file##*/} #remove the path value
    name=${name%.*} #remove any specified port(e.g. ":80")
    html2text $file > $evaluatorReports/$name.txt

done
