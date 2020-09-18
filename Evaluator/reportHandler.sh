#!/bin/bash

#env
root_folder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
report_folder=$root_folder/../Report
python=$root_folder/../python_dep/bin/python
stix_gen=$report_folder/stix_gen.py #STIX output generator

analyzer=$root_folder/../Analyzer #Analyzer components path
server_reports=$analyzer/tools/server/reports
other_reports=$analyzer/tools/others/reports

mitigations=$root_folder/Mitigations #xml database path
source_trees=$root_folder/AttackTrees #original dot sources path
trees=$root_folder/trees_to_generate #dot sources to edit path
vulnerabilityList=$mitigations/../vulnerabilityList.txt
report=$2
target=$3
IFS='"' #internal field separator - used to escape the double quotes
webserver_name=""
webserver_version=""
highlight="[color=red,penwidth=4]"
re_ip='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'

#report content
vuln_name=""
vuln_description=""
vuln_cve=""
vuln_cvss=""
detected_cvss=""
mitigation_description=""
snippet_apache="" #only used in case of STIX output
snippet_nginx="" #only used in case of STIX output

#functions
function setVulnerabilityName { #receives the vulnerability name
    vuln_name=$(xmllint --xpath "/Entry/Name/text()" $mitigations/$1.xml 2>&1)
}

function collectDescription { #[verbosity 0] - receives the vulnerability name

    #vulnerability description
    vuln_description=$(xmllint --xpath "/Entry/Description/text()" $mitigations/$1.xml 2>&1)

    #CVE
    vuln_cve=$(xmllint --xpath "/Entry/CVE/text()" $mitigations/$1.xml 2>&1)

    #CVSS
    vuln_cvss=$(xmllint --xpath "/Entry/CVSS3/text()" $mitigations/$1.xml 2>&1)
    if [ "$vuln_cvss" = "XPath set is empty" ]; then #if CVSSv3 score is not available
        vuln_cvss=$(xmllint --xpath "/Entry/CVSS2/text()" $mitigations/$1.xml 2>&1)
        if [ "$vuln_cvss" != "XPath set is empty" ]; then #if CVSSv2 score is available
            detected_cvss="2"
        else
            detected_cvss="0" #missing cvss
        fi
    else
        detected_cvss="3"
    fi
}

function collectMitigation { #[used in verbosity 0] - receives the vulnerability name
    mitigation_description=$(xmllint --xpath "/Entry/Mitigation/Textual/text()" $mitigations/$1.xml 2>&1)
}

function collectSnippet { #[used in verbosity 1] - receives the vulnerability name, webserver name and version
    
    webserver=$(echo $2 | tr '[:upper:]' '[:lower:]') #forcing webserver name in lowercase
    snippet=$(xmllint --xpath "/Entry/Mitigation/Snippet/$webserver/text()" $mitigations/$1.xml 2>&1)
    if [ "$snippet" = "XPath set is empty" ]; then #if no snippet is available
        echo "No snippet available for $2 yet" >> $report
    else
        echo "$snippet" >> $report
    fi
    echo "" >> $report
}
function collectAllSnippets { #receives the vulnerability name - STIX related

    snippet_apache=$(xmllint --xpath "/Entry/Mitigation/Snippet/apache/text()" $mitigations/$1.xml 2>&1)
    snippet_nginx=$(xmllint --xpath "/Entry/Mitigation/Snippet/nginx/text()" $mitigations/$1.xml 2>&1)
}

function exportReports { #[used in verbosity 2] - does not receive any input
    
    echo "*Copying internal reports*"
    mkdir $report_folder/raw_reports
    cp $server_reports/* $report_folder/raw_reports/ 2>/dev/null #suppressing the warnings caused by analysis not executed
    cp $other_reports/* $report_folder/raw_reports/ 2>/dev/null #same as above
}

function highlightTree { #[used in verbosity 3] - receives the vulnerability name
    for tree in $trees/*.dot; do #for each .dot in $trees
        sed -i 's/\/\*.*[[:space:]]'$1'[[:space:]].*\*\/$/'$highlight'/gI' $tree #highlighting the lines containing the vulnerability name
    done
}

function generateTrees { #[used in verbosity 3] - does not receive any input
    for tree in $trees/*.dot
    do
        name="${tree%.*}" #remove the .dot extension
        dot -Tpng $tree -o "$report_folder/${name##*/}.png"
    done
    echo "Attack trees rendered successfully!"
}

#START (receives verbosityLevel reportPath and target(URL/IP) )
numDetections=$(cat $vulnerabilityList | wc -l) #counts the number of detected issues (eventual webserver included)

## WEBSERVER DETECTION
webserver=$(cat vulnerabilityList.txt |grep -i "webserver: ")
if [ -z "$webserver" ]; then #if the tool did not detect the webserver
    echo "Webserver not detected, defaulting to Apache"
    webserver_name="Apache"
else #if the tool DID detect the webserver
    numDetections=$[numDetections-1] #remove the detected webserver from the count
    webserver=$(echo $webserver | cut -d ' ' -f 2 ) #remove the "webserver: " part
    if [[ $webserver == *"/"* ]]; then #if the tool detected a version
        webserver_name=$(echo $webserver | cut -d '/' -f 1 ) #split the file at the "/" and take the first part
        webserver_version=$(echo $webserver | cut -d '/' -f 2 ) #split at "/", take the second part
        if [[ $webserver_version == *" "* ]]; then #if the version number contains unnecessary information
            webserver_version=$(echo $webserver_version | cut -d ' ' -f 1 ) #remove them (e.g. " (Ubuntu)")
        fi
    else
        webserver_name=$webserver
    fi
fi

echo "$numDetections problems detected">> $report #prints the number of detected issues (without counting the webserver entry)
echo "*Collecting the mitigations*"

if [[ "$1" > 2 ]]; then #if the user requested the highlighted trees
    cp $source_trees/* $trees/ #copy the sources to be edited
fi

while read entry; do #for each entry in the vulnerability list

    if [[ $entry != "webserver: "* ]];then #if the entry is not a webserver (which has already been handled)
        setVulnerabilityName $entry #extracts the name of the vulnerability
        collectDescription $entry #extract its description
        collectMitigation $entry #extract its mitigation
        #collectSnippet $entry $webserver_name $webserver_version #extract the snippet [webserver_version is currently unused]

        if [ "$1" -eq "$1" ] 2> /dev/null;then #if the user has NOT requested a special output format ($1 being a number) [true if they are algebraically equal]
            if [ -f "$mitigations/$entry".xml ]; then #if the file exists
                
                echo "## $vuln_name" >> $report #write the name in the report
                echo "" >> $report
                
                #collectDescription
                echo $vuln_description >> $report
                echo "" >> $report
                echo "" >> $report
                
                if [ "$vuln_cve" != "XPath set is empty" ]; then #if no CVE ID is available
                    echo "**CVE: **" >> $report
                    echo "$vuln_cve" >> $report
                    echo "" >> $report #additional newline because CVSS will always come after CVE
                fi

                if ! [ "$detected_cvss" = "0" ]; then
                    if [ "$detected_cvss" = "2" ]; then
                        echo "**CVSSv2 score: **" >> $report
                    else
                        echo "**CVSSv3 score: **" >> $report
                    fi
                    echo "$vuln_cvss" >> $report
                    echo "" >> $report
                fi

                echo "#### Mitigation">> $report
                echo "" >> $report
                #collectMitigation 
                echo $mitigation_description >> $report
                echo "" >> $report

                if [[ "$1" -gt 0 ]]; then
                    echo "#### Code Snippet">> $report
                    echo "" >> $report
                    collectSnippet $entry $webserver_name $webserver_version #extract the snippet [webserver_version is currently unused]
                    echo "" >> $report
                    
                    if [[ "$1" -gt 2 ]]; then #if the user requested the highlighted trees
                        highlightTree $entry #highlight its edge (the tree will be generated later)
                    fi
                fi
            else
                echo "## $entry">> $report
                echo "No details available">> $report
            fi
        else
            if [ "$1" = "x" ]; then #if the STIX output is required
                rm $2 2>/dev/null #remove the unused markdown report
                collectAllSnippets $entry

                # Create a temporary python script to generate the STIX bundle (removing the newlines)
                coa_name=$(echo $vuln_name"_coa")
                mitigation_description=$(echo $mitigation_description|tr -d '\n')
                snippet_apache=$(echo $snippet_apache|tr -d '\n')
                snippet_nginx=$(echo $snippet_nginx|tr -d '\n')
                vuln_name=$(echo $vuln_name|tr -d '\n')
                vuln_description=$(echo $vuln_description|tr -d '\n')

                ## mitigations' double quotes escaping
                read -ra ADDR <<< "$snippet_apache" # split the content using IFS as separator 
                snippet_apache=""
                for i in "${ADDR[@]}"; do # for each fragment
                    snippet_apache="$snippet_apache $i'" #rebuild the variable adding proper double quoting escaping
                done
                
                read -ra ADDR <<< "$snippet_nginx"
                snippet_nginx=""
                for i in "${ADDR[@]}"; do 
                    snippet_nginx="$snippet_nginx $i'"
                done

                ## script construction
                echo "from stix2 import CourseOfAction" >> $stix_gen
                echo "from stix2 import Vulnerability " >> $stix_gen
                echo "from stix2 import Relationship" >> $stix_gen
                echo "from stix2 import Sighting" >> $stix_gen
                echo "from stix2 import ObservedData" >> $stix_gen
                echo "from stix2 import URL" >> $stix_gen
                echo "from stix2 import IPv4Address" >> $stix_gen
                echo "from stix2 import Bundle" >> $stix_gen
                echo "from datetime import datetime" >> $stix_gen
                echo "timestamp = datetime.now()" >> $stix_gen
                echo "coa = CourseOfAction(type=\"course-of-action\",name=\"$coa_name\",description=\"$mitigation_description\",x_actions=[{\"mitigation_apache\":\"${snippet_apache::-1}\",\"mitigation_nginx\":\"${snippet_nginx::-1}\"}], allow_custom=True)" >> $stix_gen #::-1 because the last character is an extra '
                echo "vuln= Vulnerability(type=\"vulnerability\",name=\"$vuln_name\",description=\"$vuln_description\")" >> $stix_gen
                echo "mitigates = Relationship(coa, 'mitigates', vuln)" >> $stix_gen

                if [[ $target =~ $re_ip ]] ; then #if the target is an URL
                    echo "observed_object=IPv4Address(value=\"$target\")" >> $stix_gen #use the IPv4 object
                else
                    echo "observed_object=URL(value=\"$target\")" >> $stix_gen #URL otherwise
                fi

                echo "observed_data=ObservedData(first_observed=timestamp,last_observed=timestamp,number_observed=1,objects={ 0: observed_object })" >> $stix_gen
                echo "sight=Sighting(vuln, observed_data_refs=[observed_data])" >> $stix_gen
                echo "bundle = Bundle(coa, mitigates, vuln, sight, observed_data)" >> $stix_gen
                
                echo "f = open(\"$report_folder/$vuln_name.json\", \"w\")" >> $stix_gen
                echo "f.write(str(bundle)+\"\n\")" >> $stix_gen
                echo "f.close()" >> $stix_gen

                
                $python $stix_gen #runs the script
                rm $stix_gen
            fi
        fi
    fi
done < $vulnerabilityList

if [ "$1" -eq "$1" ] 2> /dev/null;then #if the user has NOT requested a special output format
    if [[ "$1" -gt 1 ]]; then #move the internal reports
        exportReports
    fi

    if [[ "$1" -gt 2 ]]; then #generate the highlighted trees
        generateTrees
    fi
report_name=${report##*/} #remove the path
report_name=${report_name%.*} #remove the extension
bash $root_folder/../utility/markdown.sh $report > $report_folder/$report_name.html #convert to HTML
rm $report
fi
