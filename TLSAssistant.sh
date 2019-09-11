#!/bin/bash

#env
root_folder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
report_folder=$root_folder/Report

analyzer=$root_folder/Analyzer #Analyzer components path
server_reports=$analyzer/tools/server/reports
other_reports=$analyzer/tools/others/reports

evaluator=$root_folder/Evaluator #Evaluator components path
evaluator_reports=$evaluator/reports_to_evaluate
evaluator_trees=$evaluator/trees_to_generate

reportHandler=$root_folder/Evaluator/ReportHandler

#regular expressions
re_integer='^[0-9]+$'
re_url='^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$'
re_ip='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'

#functions
function cleanup { #removing old reports (suppressing the warnings)
    rm -r $server_reports/* 2>/dev/null
    rm -r $other_reports/* 2>/dev/null
    rm -r $evaluator/vulnerabilityList.txt 2>/dev/null
    rm -r $evaluator_reports/* 2>/dev/null
    rm -r $evaluator_trees/* 2>/dev/null
}

function printHelp {
    echo "Usage: \"bash TLSAssistant.sh <parameters>\""
    echo
    echo "where"
    echo " PARAMETERS"
    echo "    -h|--help:                     show the help"                       #help
    echo "    -s|--server [URL|IP] {port}:   analyze a server, default port: 443" #server
    echo "    -a|--apk <file>:               check an apk"                        #apk
    echo "    -v [0|1|2|3]:                  verbosity level"                     #report type
    echo
    echo " VERBOSITY LEVEL"
    echo "    0: mitigations'description"
    echo "    1: previous + code snippets [default]"
    echo "    2: previous + tools'individual reports"
    echo "    3: previous + highlighted attack trees"
}

function quit {
    cleanup
    exit
}

#START
cleanup #removes previous report generations
rm -r $report_folder 2>/dev/null #removing residues files
clear #clear the terminal

#variables
analyzer_started=0 #used for edge cases (in which the welcome was printed even if the HELP was requested)
verbosity=1

if [[ $# -lt 1 ]] ; then #if help requested (or not enough parameters)
    printHelp
    quit
fi

echo -e "\033[1m################\033[0m"
echo -e "\033[1m# TLSAssistant #\033[0m"
echo -e "\033[1m################\033[0m"

#report folder creation
mkdir $root_folder/Report
echo "# TLSAssistant report">> $report_folder/Report.md
report=$report_folder/Report.md
dt=$(date '+%H:%M:%S, %d/%m/%Y');
echo "Scan started at $dt">> $report
echo "">> $report

while [[ $# -gt 0 ]] #for each argument (number greater than zero)
do
    mode=$1
    case $mode in #check the value
        -h|--help)
            printHelp
            quit
            ;;
        -s|--server)
            if ! [[ $2 =~ $re_url ]] ; then #check if it is a correct hostname
                if ! [[ $2 =~ $re_ip ]] ; then #or a correct IP
                    if ! [[ $2 = "localhost" ]] ; then #or the "localhost" string
                        echo "Invalid URL"
                        quit
                    fi
                fi
            fi

            if [ "$analyzer_started" -eq 0 ]; then #to avoid premature echoes
                echo -e "\033[7mStarting Analyzer\033[0m"
                analyzer_started=1
            fi

            if ! [[ $3 =~ $re_integer ]] ; then #check if $3 is a port number. If it is not, fallback to the default one
                echo "Server: $2:443">> $report
                echo "">> $report
                cd $analyzer
                bash checkServer.sh $2
                cd $root_folder
                shift 2 #skip argument and server
            else #otherwise, pass it
                echo "Server: $2:$3">> $report
                echo ""
                cd $analyzer
                bash checkServer.sh $2 $3
                cd $root_folder
                shift 3 #skip argument, server and port
            fi
            ;;
        -a|--apk)
            if ! { [ -f "$2" ] && [ ${2: -4} 1== ".apk" ]; }; then #if the argument not a valid file
                echo "$2 is not valid file"
                quit
            fi

            if [ "$analyzer_started" -eq 0 ]; then #to avoid premature echoes
                echo -e "\033[7mStarting Analyzer\033[0m"
                analyzer_started=1
            fi

            echo "Apk: $2">> $report
            echo "">> $report
            cd $analyzer
            bash checkApk.sh $2
            sleep 10
            cd $root_folder
            shift 2 #skip argument and file
            ;;
        -v) #verbosity level
            if [ "$2" -ge 0 -a "$2" -le 3 ]; then #if the value is in the accepted range
                verbosity=$2
                shift 2 #skip argument and value
            else
                echo "Unexpected argument(s)"
                quit
            fi
            ;;
        *)
            echo "Unexpected argument(s)"
            quit
            ;;
    esac
done

echo -e "\033[7mStarting Evaluator\033[0m"

cd $evaluator
bash enumerator.sh #enumerator
bash reportHandler.sh $verbosity $report #report generator
cd $root_folder


echo -e "\033[1mReport saved in $report_folder\033[0m"
#END
quit
