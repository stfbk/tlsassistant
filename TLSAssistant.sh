#!/bin/bash

#env
root_folder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
report_folder=$root_folder/Report
report="" #currently empty, will be initialized in the "initialize_report" function
target="" #currently empty, will be initialized if the users wants to analyze a webserver

analyzer=$root_folder/Analyzer #Analyzer components path
server_reports=$analyzer/tools/server/reports
other_reports=$analyzer/tools/others/reports

evaluator=$root_folder/Evaluator #Evaluator components path
evaluator_reports=$evaluator/reports_to_evaluate
evaluator_trees=$evaluator/trees_to_generate

reportHandler=$root_folder/Evaluator/ReportHandler
python=$root_folder/python_dep/bin/python

#regular expressions
re_integer='^[0-9]+$'
re_url='^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$'
re_ip='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'

#functions
function cleanup { #removing old reports (suppressing the warnings)
    rm -r $server_reports/* 2>/dev/null
    rm -r $other_reports/* 2>/dev/null
    rm -r $evaluator/vulnerabilityList.txt 2>/dev/null
    rm -r $evaluator/vulnerabilityList_SUPER.txt 2>/dev/null
    rm -r $evaluator_reports/* 2>/dev/null
    rm -r $evaluator_trees/* 2>/dev/null
    rm -r $root_folder/subdomains.txt 2>/dev/null
}

function printHelp {
    echo "Usage: \"bash TLSAssistant.sh <parameters>\""
    echo
    echo "where"
    echo " PARAMETERS"
    echo "    -h|--help:                     show the help"                                   #help
    echo "    -s|--server [URL|IP] {port}:   analyze a server, default port: 443"             #server
    echo "    -d|--domain <URL>:             analyze the subdomains of a given website"       #subdomains
    echo "    -l|--list <file>               analyze the provided hosts list (one per line) " #list
    echo "    -a|--apk <file>:               check an apk"                                    #apk
    echo "    -x|--stix:                     STIX output format"                              #STIX output format
    echo "    -v [0|1|2|3]:                  verbosity level"                                 #report type
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

function initialize_report {
    if ! [ -z "$1" ] #if the caller specified a name
    then
        report=$report_folder/Report_$1.md
    else
        report=$report_folder/Report.md
    fi

    echo "# TLSAssistant report">> /$report
    dt=$(date '+%H:%M:%S, %d/%m/%Y');
    echo "Scan started at $dt">> $report
    echo "">> $report
}

function subdomains_collector {    
    
    host=$1
    #extract the main domain (in case of incorrect input)
    dots=$(grep -o "\." <<<"$1" | wc -l) #counts the number of dots (1= main, more= subdomains)
    if [ "$dots" -gt "1" ]; then #if the host is a sub-domain
        host=$(expr match "$1" '.*\.\(.*\..*\)') #to retrieve the main domain
    fi

    $python utility/ctfr/ctfr.py -d $host -o $root_folder/subdomains_tmp.txt &> /dev/null #generating the subdomain list (based on their certificates)
    sort -u $root_folder/subdomains_tmp.txt > $root_folder/subdomains.txt #removing duplicate lines (caused by multiple certificates available)
    rm $root_folder/subdomains_tmp.txt
    sed -i '/\*/d' $root_folder/subdomains.txt #deleting the wildcard certificate entries (lines containing an asterisk)
    echo $host >> $root_folder/subdomains.txt #adding the main domain to the list
    echo "Subdomains collected!"
}

function list_analyzer {
    echo "The analysis may take a while"
    while read entry; do #for each hostname

        echo ""
        echo -e '\033[1mAnalyzing \033[0m'$entry
        initialize_report $entry
        echo "Server: $entry:443">> $report
        echo "">> $report
        cd $analyzer
        bash checkServer.sh $entry               #analyzer
        cd $root_folder
        cd $evaluator
        bash enumerator.sh                       #enumerator
        bash reportHandler.sh $verbosity $report #report generator
        cd $root_folder
        cleanup
    done < $1
}

#START
cleanup #removes previous report generations
rm -r $report_folder 2>/dev/null #removing residues files (this this the only needed usage thus the exclusion from the "cleanup" function) 
clear #clear the terminal

#variables
analyzer_started=0 #used for edge cases (in which the welcome was printed even if the HELP was requested)
verbosity=1

if [[ $# -lt 1 ]] ; then #if help requested (or not enough parameters)
    printHelp
    quit
fi

echo -e "\033[7m################\033[0m"
echo -e "\033[7m# TLSAssistant #\033[0m"
echo -e "\033[7m################\033[0m"

if [[ ! -d $root_folder/python_dep ]]; then #if the INSTALLER has never been called
    echo ""
    echo "Run INSTALL.sh to set the environment first"
    exit 1
fi

#report folder creation
mkdir $root_folder/Report
initialize_report

while [[ $# -gt 0 ]] #for each argument (number greater than zero)
do
    mode=$1
    case $mode in #check the value
        -h|--help)
            rm -r $report_folder 2>/dev/null
            printHelp
            quit
            ;;
        -s|--server)
            target=$2
            if ! [[ $2 =~ $re_url ]] ; then #check if it is a correct hostname
                if ! [[ $2 =~ $re_ip ]] ; then #or a correct IP
                    if ! [[ $2 = "localhost" ]] ; then #or the "localhost" string
                        echo "Invalid URL"
                        quit
                    fi
                fi
            fi

            if [ "$analyzer_started" -eq 0 ]; then #to avoid premature echoes
                echo -e "\033[1mStarting Analyzer\033[0m"
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
        -d|--domain)
            echo -e '\033[1mNote: this feature will not check subdomains covered by a wildcard certificate\033[0m'
            echo ""
            if ! [[ $2 =~ $re_url ]] ; then #check if it is a correct hostname
                echo "Invalid URL"
                quit
            fi
            rm -r $report_folder/* 2>/dev/null #remove the intermediate report
            subdomains_collector $2
            list_analyzer subdomains.txt
            mv subdomains.txt $report_folder
            echo -e '\033[1mSubdomain analysis completed!\033[0m'
            quit
            ;;
        -l|--list)
            if ! { [ -f "$2" ] && [ ${2: -4} 1== ".txt" ]; }; then #if the argument not a text file
                echo "$2 is not valid file"
                quit
            fi
            rm -r $report_folder/* 2>/dev/null #remove the intermediate report
            list_analyzer $2
            echo ""
            echo -e '\033[1mList analysis completed!\033[0m'
            quit
            ;;
        -a|--apk)
            if ! { [ -f "$2" ] && [ ${2: -4} == ".apk" ]; }; then #if the argument not an apk
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
            echo $2
            cd $root_folder
            whereisfile=$(realpath ${2})
            #echo $whereisfile
            cd $analyzer
            bash checkApk.sh ${whereisfile}&
            wait
            cd $root_folder
            shift 2 #skip argument and file
            ;;
        -x|--stix) #STIX output 
            verbosity="x"
            shift
            ;;
        -v) #verbosity level
            if [ "$2" -eq "$2" ] 2> /dev/null; then #if the user has NOT requested a special output format [true if they are algebraically equal]
                if [ "$2" -ge 0 -a "$2" -le 3 ]; then #if the value is in the accepted range
                    verbosity=$2
                    shift 2 #skip argument and value
                else
                    echo "Unexpected argument(s)"
                    quit
                fi
            else
                shift 2
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
bash reportHandler.sh $verbosity $report $target #report generator
cd $root_folder


echo -e "\033[1mReport saved in $report_folder\033[0m"
#END
quit
