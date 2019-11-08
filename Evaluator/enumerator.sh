#!/bin/bash

#env
root_folder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
toolReports=$root_folder/reports_to_evaluate
webserver=""

##functions definition
function assistant_enumerator {

    #webserver detection
    if grep -i -q "Server: " $toolReports/assistant.txt; then 
        webserver=$(grep -i "Server: " $toolReports/assistant.txt | grep -oiP '(?<=Server: ).*')
        echo "webserver: $webserver">> $root_folder/vulnerabilityList.txt #sending "webserver: <webserverName>[/<version>]"
        echo "- webserver: $webserver"
    fi

    #HTTP available
    if cat $toolReports/assistant.txt |grep -q -i "HTTP available"; then
        echo "- detected: HTTP available"
    fi

    #HTTPS enforcing
    if cat $toolReports/assistant.txt |grep -q -i "HTTPS not enforced"; then
        echo "HTTPS_not_enforced">> $root_folder/vulnerabilityList.txt
        echo "- detected: HTTPS not enforced"
    fi

    #HSTS
    if cat $toolReports/assistant.txt |grep -q -i "HSTS not set"; then
        echo "HSTS_not_set">> $root_folder/vulnerabilityList.txt
        echo "- detected: HSTS not set"
    fi

    #HSTS PRELOADING
    if cat $toolReports/assistant.txt |grep -q -i "HSTS not preloaded"; then
        echo "HSTS_not_preloaded">> $root_folder/vulnerabilityList.txt
        echo "- detected: HSTS not preloaded"
        
        #SSL STRIPPIING (has another prerequisite)
        if cat $toolReports/assistant.txt |grep -q -i "HTTP_available"; then
            echo "- detected: SSL stripping"
        fi
    fi
}

function extended_master_enumerator {

    #3SHAKE
    if grep "TLSv1.2" $toolReports/extended_master_report.txt |grep -q "vulnerable"; then
        echo "3SHAKE">> $root_folder/vulnerabilityList.txt
        echo "- detected: 3SHAKE"
    fi
}
function mallodroid_enumerator {

    #Unsecure TrustManagers
    if grep -q "broken=\"True\"" $toolReports/mallodroid_report.txt; then
        echo "TRUST_MANAGER">> $root_folder/vulnerabilityList.txt
        echo "- detected: unsecure Android TrustManager"
    fi
}

function testssl_enumerator {

    #Bar Mitzvah
    if grep "RC4" $toolReports/testssl_report.txt |grep -q "VULNERABLE"; then
        echo "MITZVAH">> $root_folder/vulnerabilityList.txt
        echo "- detected: Bar Mitzvah"
    fi

    #BREACH
    if grep "BREACH" $toolReports/testssl_report.txt |grep -q "potentially NOT ok"; then
        echo "BREACH">> $root_folder/vulnerabilityList.txt
        echo "- detected: BREACH"
    fi

    #CRIME
    if grep "CRIME" $toolReports/testssl_report.txt |grep -q "VULNERABLE (NOT ok)"; then
        echo "CRIME">> $root_folder/vulnerabilityList.txt
        echo "- detected: CRIME"
    fi

    #DROWN
    if grep "DROWN" $toolReports/testssl_report.txt |grep -q "SSLv2 offered"; then
        echo "DROWN">> $root_folder/vulnerabilityList.txt
        echo "- detected: DROWN"
    fi

    #Lucky13
    if grep "LUCKY13" $toolReports/testssl_report.txt |grep -q "VULNERABLE"; then
        echo "LUCKY13">> $root_folder/vulnerabilityList.txt
        echo "- detected: LUCKY13"
    fi

    #POODLE
    if grep "POODLE" $toolReports/testssl_report.txt |grep -q "VULNERABLE (NOT ok)"; then
        echo "POODLE">> $root_folder/vulnerabilityList.txt
        echo "- detected: POODLE"
    fi

    #RC4 NOMORE
    if grep "RC4" $toolReports/testssl_report.txt |grep -q "VULNERABLE"; then
        echo "NOMORE">> $root_folder/vulnerabilityList.txt
        echo "- detected: RC4 NOMORE"
    fi

    #ROBOT
    if grep "ROBOT" $toolReports/testssl_report.txt |grep -q "VULNERABLE (NOT ok)"; then
        echo "ROBOT">> $root_folder/vulnerabilityList.txt
        echo "- detected: ROBOT"
    fi

    #Sweet32
    if grep "SWEET32" $toolReports/testssl_report.txt |grep -q "VULNERABLE"; then
        echo "SWEET32">> $root_folder/vulnerabilityList.txt
        echo "- detected: SWEET32"
    fi

    #Client-Initiated Renegotiation DoS
    if grep "Secure Client-Initiated Renegotiation" $toolReports/testssl_report.txt |grep -q "VULNERABLE (NOT ok)"; then
        echo "RENEGOTIATION">> $root_folder/vulnerabilityList.txt
        echo "- detected: Client-Initiated Renegotiation DoS"
    fi

    #Missing Certificate Transparency
    if ! grep "Certificate Transparency" $toolReports/testssl_report.txt |grep -q "yes"; then
        echo "TRANSPARENCY">> $root_folder/vulnerabilityList.txt
        echo "- detected: Missing Certificate Transparency"
    fi
}

function tlsfuzzer_enumerator {

    #SLOTH
    if ! grep -q "successful: 0" $toolReports/tlsfuzzer_report.txt; then
        echo "SLOTH">> $root_folder/vulnerabilityList.txt
        echo "- detected: SLOTH"
    fi
}

echo
echo "---Begin vulnerability enumeration---"

touch $root_folder/vulnerabilityList.txt
for file in $toolReports/*; do #for each report available

    file=${file##*/} #remove the path value
    case $file in #invoke the proper function to analyze the report
        assistant.txt)
            assistant_enumerator #internal function call
            ;;
        testssl_report.txt)
            testssl_enumerator #internal function call
            ;;
        extended_master_report.txt)
            extended_master_enumerator #internal function call
            ;;
        tlsfuzzer_report.txt)
            tlsfuzzer_enumerator #internal function call
            ;;
        mallodroid_report.txt)
            mallodroid_enumerator #internal function call
            ;;
    esac
done

echo
echo "Enumeration completed successfully!"