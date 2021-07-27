#!/bin/bash

#env
root_folder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
toolReports=$root_folder/reports_to_evaluate
python=$root_folder/../python_dep/bin/python
tools=$root_folder/../Analyzer/tools/others #other tools path (starting from the project root)
parser="${tools}/super_config/parser.py"
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

function mallodroid_enumerator {

    #Unsecure TrustManagers
    if grep -q "broken=\"True\"" $toolReports/mallodroid_report.txt; then
        echo "TRUST_MANAGER">> $root_folder/vulnerabilityList.txt
        echo "- detected: unsecure Android TrustManager"
    fi
}

function testssl_enumerator {

    #3SHAKE
    if ! grep -Pzq "e\s*x\s*t\s*e\s*n\s*d\s*e\s*d\s*m\s*a\s*s\s*t\s*e\s*r\s*s\s*e\s*c\s*r\s*e\s*t\s*/\s*#\s*2\s*3" $toolReports/testssl_report.txt ; then
        echo "3SHAKE">> $root_folder/vulnerabilityList.txt
        echo "- detected: 3SHAKE"
    fi

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

    #Renegotiation attack
    if ! grep "(RFC 5746)" $toolReports/testssl_report.txt |grep -q "supported (OK)"; then
        echo "RENEGOTIATION">> $root_folder/vulnerabilityList.txt
        echo "- detected: unsecure renegotiation"
    fi

    #Missing Certificate Transparency
    if ! grep "Certificate Transparency" $toolReports/testssl_report.txt |grep -q "yes"; then
        echo "TRANSPARENCY">> $root_folder/vulnerabilityList.txt
        echo "- detected: Missing Certificate Transparency"
    fi
}

function tlsfuzzer_enumerator {
    #client auth zone
    #mutual auth check
    handshake_status=$(grep -o "AssertionError: Unexpected message from peer:" $toolReports/tlsfuzzer_report.txt|wc -l) #ok value 0, but it will generally fail with this value ==5
    sanity_mutual=$(grep -o "sanity" $toolReports/tlsfuzzer_report.txt|wc -l) #ok value 2
    md5forced=$(grep -o "MD5 forced" $toolReports/tlsfuzzer_report.txt|wc -l) #ok value 2
    certificateverify=$(grep -o "TLSv1.1 signature in TLSv1.2 Certificate Verify" $toolReports/tlsfuzzer_report.txt|wc -l) #valore sano 1
    sumof_mutual=$(($md5forced + $certificateverify))
    
    #md5 sigs check
    md5first=$(grep -o "MD5 first" $toolReports/tlsfuzzer_report_sigs.txt|wc -l) #ok value 2
    sanity_md5sigs=$(grep -o "sanity" $toolReports/tlsfuzzer_report_sigs.txt|wc -l) #ok value 2
    
    #clienthello check
    clienthellomd5=$(grep -o "only-md5-rsa-signature_algorithm" $toolReports/tlsfuzzer_report_clienthello.txt|wc -l) #ok value 1
    sanity_clienthellomd5=$(grep -o "sanity" $toolReports/tlsfuzzer_report_clienthello.txt|wc -l) #ok value 2
    unknownsignatures=$(grep -o "unknown-signature_algorithm-numbers" $toolReports/tlsfuzzer_report_clienthello.txt|wc -l) #ok value 1
    sumof_clienthello=$(($clienthellomd5 + $unknownsignatures))
    
    #legacy ciphers TLS 1.3
    legacytls13=$(grep -o "rsa_pkcs1_md5 signature" $toolReports/tlsfuzzer_report_tls13sigs.txt|wc -l) #ok value 1
    sanity_legacytls13=$(grep -o "sanity" $toolReports/tlsfuzzer_report_tls13sigs.txt|wc -l) #ok value 2
    
    #SLOTH Mutual
    if ! grep -q -w "FAIL: 0" $toolReports/tlsfuzzer_report.txt; then # if it's not 0

        if [ $handshake_status -eq 5 ]; then #checking if no client auth
            echo -e "- \e[30;44m[INFO]\e[0m: SLOTH Handshake failed, the server probably isn't using a mutual authentication."

        elif [ $sanity_mutual -gt 2 ]; then #checking if sanity check is good
            echo -e "- \e[30;43m[WARNING]\e[0m: sanity check FAILED, could not check for Mutual Authentication SLOTH."
            
        elif [ $sumof_mutual -gt 3 ]; then #checking if sloth
            echo "SLOTH">> $root_folder/vulnerabilityList.txt
            echo "- detected: SLOTH - Mutual Auth"
        fi
    else
        echo "- No Mutual Auth SLOTH Detected."
    fi
    echo 
    #md5 sigs
    if ! grep -q -w "FAIL: 0" $toolReports/tlsfuzzer_report_sigs.txt; then # if it's not 0

        if [ $sanity_md5sigs -gt 2 ]; then #checking if sanity check is good
            echo -e "- \e[30;43m[WARNING]\e[0m: sanity check FAILED, could not check for MD5 sigs SLOTH."
            echo -e "- \e[30;44m[INFO]\e[0m: This check only works with RSA Certificates and with TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA or TLS_DHE_RSA_WITH_AES_128_CBC_SHA enabled server side."
            
        elif [ $md5first -gt 2 ]; then #checking if sloth
            echo "SLOTH_MD5_Signature">> $root_folder/vulnerabilityList.txt
            echo "- detected: SLOTH - MD5 Signature"
        else
            echo "- No MD5 Signature SLOTH Detected."
        fi

    else
        echo "- No MD5 Signature SLOTH Detected."
    fi
    echo 

    #md5 sigs forced
    if ! grep -q -w "FAIL: 0" $toolReports/tlsfuzzer_report_clienthello.txt; then # if it's not 0

        if [ $sanity_clienthellomd5 -gt 2 ]; then #checking if sanity check is good
            echo -e "- \e[30;43m[WARNING]\e[0m: sanity check FAILED, could not check for MD5 Signature ClientHello Forced SLOTH."
            echo -e "- \e[30;44m[INFO]\e[0m: This check only works with RSA Certificates and with TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 enabled server side."  
            
        elif [ $sumof_clienthello -gt 2 ]; then #checking if sloth
            echo "SLOTH">> $root_folder/vulnerabilityList.txt
            echo "- detected: SLOTH - MD5 Signature ClientHello Forced"
        else
            echo "- No MD5 Signature ClientHello Forced SLOTH Detected."
        fi
    else
        echo "- No MD5 Signature ClientHello Forced SLOTH Detected."
    fi
    echo 

    #tls13 legacy md5
    if ! grep -q -w "FAIL: 0" $toolReports/tlsfuzzer_report_tls13sigs.txt; then # if it's not 0

        if [ $sanity_legacytls13 -gt 2 ]; then #checking if sanity check is good
            echo -e "- \e[30;43m[WARNING]\e[0m: sanity check FAILED, could not check for TLS 1.3 Legacy md5 signatures SLOTH."
            echo -e "- \e[30;44m[INFO]\e[0m: The server probably isn't using TLS 1.3."
            
        elif [ $legacytls13 -gt 1 ]; then #checking if sloth
            echo "SLOTH_MD5_Signature_TLS13">> $root_folder/vulnerabilityList.txt
            echo "- detected: SLOTH - MD5 Signature TLS 1.3 Detected"
        else
            echo "- No MD5 Signature TLS 1.3 SLOTH Detected."
        fi
    else
        echo "- No MD5 Signature TLS 1.3 SLOTH Detected."
    fi
    echo 
}


function super_enumerator() {
    $python ${parser} $toolReports/super_report.txt -b -m $root_folder/Mitigations -v 3 -s \<br\> >$root_folder/vulnerabilityList_SUPER.txt #Parser for super results.
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
        tlsfuzzer_report.txt)
            tlsfuzzer_enumerator #internal function call
            ;;
        mallodroid_report.txt)
            mallodroid_enumerator #internal function call
            ;;
        super_report.txt)
            super_enumerator #internal function call
            ;;
    esac
done

echo
echo "Enumeration completed successfully!"
