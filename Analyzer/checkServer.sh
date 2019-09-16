#!/bin/bash

#env
root_folder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
tools=$root_folder/tools/server #server tool path (starting from the project root)
report=$tools/reports #server report path (starting from the project root)
evaluatorReports=$root_folder/../Evaluator/reports_to_evaluate
python=$root_folder/../python_dep/bin/python

##functions definition
function s_echo {
    callingFunction="${FUNCNAME[1]}"
    echo "[$callingFunction] $1"
}

function extended_master_checker {
    version="0.1" #version
    extended_master_folder=$tools/TLS_Extended_Master_Checker #location (folder)

    cd "$extended_master_folder"
    s_echo "version: $version"
    s_echo "Analyzing..."
    $python TLS_Extended_Master_Checker.py $1 $2 | aha -t ${FUNCNAME[0]} > $report/extended_master_report.html
    s_echo "Report generated successfully!"
    echo
    cd $root_folder
}

function testssl.sh {
    version="3.0rc5" #version
    testssl_folder=$tools/testssl.sh-$version #location (folder)

    re_url='^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$'
    if [[ $1 =~ $re_url ]]; then #if the target is provided via hostname
        args="-p -P -h -U -S --ip one" #to show, in order: protocols, preferences, header, vulnerabilities, server defaults and scanning only one IP (hostname case)
    else
        args="-p -P -h -U -S" #same as before but in case of target IP
    fi

    cd $testssl_folder
    s_echo "version: $version"
    s_echo "Analyzing..."
    bash testssl.sh $args $1:$2 | aha -t ${FUNCNAME[0]} > $report/testssl_report.html
    s_echo "Report generated successfully!"
    echo
    cd $root_folder
}

function tlsfuzzer { #SLOTH checker
    version="0.0.1" #version
    sloth_checker=$tools/tlsfuzzer #location (folder)
    cert_location=$tools/utils #certificate location

    cd $sloth_checker
    s_echo "version: $version"
    s_echo "Analyzing..."
    PYTHONPATH=. $python $sloth_checker/scripts/test-certificate-verify.py -h $1 -p $2 -k $cert_location/localuser.key -c $cert_location/localuser.crt | aha -t ${FUNCNAME[0]} > $report/tlsfuzzer_report.html
    s_echo "Report generated successfully!"
    echo
    cd $root_folder
}

function assistant {
    host=$1
    re_url='^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$'

    #--------webserver detection 
    curl -s --head http://$host | grep "Server" >> $report/assistant.txt 

    if [[ $host =~ $re_url ]]; then #if the target is provided via hostname, do the HTTPS-related checks

        touch $report/assistant.txt
        google_hsts=$(curl -s https://cs.chromium.org/codesearch/f/chromium/src/net/http/transport_security_state_static.json)
        mozilla_hsts=$(curl -s https://hg.mozilla.org/mozilla-central/raw-file/tip/security/manager/ssl/nsSTSPreloadList.inc)

        #--------HTTPS enforcing
        if curl -s --head http://$host | grep -i -q "moved permanently"; then #condition 1
            if curl -s --head http://$host | grep -i -q "location: https"; then #condition 2
                echo "HTTPS enforced">> $report/assistant.txt
            else
                echo "HTTPS not enforced">> $report/assistant.txt # domain either not configured or not following RFC specifications
            fi
        else
            echo "HTTPS not enforced">> $report/assistant.txt
        fi

        #--------HSTS
        if curl -s --head https://$host | grep -i -q "strict-transport-security"; then
            echo "HSTS set">> $report/assistant.txt
        else
            echo "HSTS not set">> $report/assistant.txt # domain either not configured or not following RFC specifications
        fi

        #--------HSTS PRELOADING
        dots=$(grep -o "\." <<<"$host" | wc -l) #counts the number of dots (1= main, more= subdomains)
        if [ "$dots" -gt "1" ]; then #if the host is a sub-domain
            host=$(expr match "$host" '.*\.\(.*\..*\)') #to retrieve the main domain
        fi
        
        if echo $google_hsts | grep -i -q $host; then #present in Google's list
            echo "HSTS preloaded">> $report/assistant.txt
        else
            if echo $mozilla_hsts | grep -i -q $host; then #present in Mozilla's list
                echo "HSTS preloaded">> $report/assistant.txt
            else
                echo "HSTS not preloaded">> $report/assistant.txt
            fi
        fi

    else
        echo "IP address provided, skipping HTTPS-related checks"
    fi
}

#cleanup
server=${1##*://} #remove any protocol mention (e.g. "https://")
server=${server%:*} #remove any specified port(e.g. ":80")
server=$(echo $server | cut -d '/' -f 1 ) #remove anything after "/" (subfolders)

if [ -z "$2" ] #verify if the user specified a port
then
    port=443 #if not, use the default value
else
    port=$2
fi

echo
echo "---Begin server scan---"
echo "Target: $server:$port"
echo

#scripts call
extended_master_checker $server $port #checks for 3SHAKE
testssl.sh $server $port #checks for TLS vulnerabilities
tlsfuzzer $server $port #checks for SLOTH
assistant $server #checks for HTTPS enforcing and HSTS

#provide the reports to the Evaluator
for file in $report/*.html; do #for each html report

    name=${file##*/} #remove the path value
    name=${name%.*} #remove the extension (e.g. ".html")
    html2text $file > $evaluatorReports/$name.txt

done
for file in $report/*.txt; do #for each txt report

    cp $file $evaluatorReports 2>/dev/null #an edge case causes an error (IP provided --> HTTPS not checked)

done
