#!/bin/bash

#env
root_folder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
user_desktop=$(xdg-user-dir DESKTOP)

analyzer=$root_folder/../Analyzer #Analyzer components path
server_reports=$analyzer/tools/server/reports
other_reports=$analyzer/tools/others/reports

mitigations=$root_folder/Mitigations #xml database path
source_trees=$root_folder/AttackTrees #original dot sources path
trees=$root_folder/trees_to_generate #dot sources to edit path
vulnerabilityList=$mitigations/../vulnerabilityList.txt
report=$2
webserver_name=""
webserver_version=""
highlight="[color=red,penwidth=4]"

#functions
function collectDescription { #[verbosity 0] - receives the vulnerability name

    xmllint --xpath "/Entry/Description/text()" $mitigations/$1.xml >> $report
    echo "" >> $report
}

function collectMitigation { #[verbosity 0] - receives the vulnerability name

    xmllint --xpath "/Entry/Mitigation/Textual/text()" $mitigations/$1.xml >> $report
    echo "" >> $report
}

function collectSnippet { #[verbosity 1] - receives the vulnerability name, webserver name and version

    snippet=$(xmllint --xpath "/Entry/Mitigation/Snippet/$2/text()" $mitigations/$1.xml 2>&1)
    if [ "$snippet" = "XPath set is empty" ]; then #if no snippet is available
        echo "No snippet available for $2 yet" >> $report
    else
        echo "$snippet" >> $report
    fi
    echo "" >> $report
}

function exportReports { #[verbosity 2] - does not receive any input

    echo "*Copying internal reports*"
    mkdir $user_desktop/TLSAssistant_report/raw_reports
    cp $server_reports/* $user_desktop/TLSAssistant_report/raw_reports/ 2>/dev/null #suppressing the warnings caused by analysis not executed
    cp $other_reports/* $user_desktop/TLSAssistant_report/raw_reports/ 2>/dev/null #same as above
}

function highlightTree { #[verbosity 3] - receives the vulnerability name
    for tree in $trees/*.dot; do #for each .dot in $trees
        sed -i 's/\/\*.*[[:space:]]'$1'[[:space:]].*\*\/$/'$highlight'/gI' $tree #highlighting the lines containing the vulnerability name
    done
}

function generateTrees { #[verbosity 3] - does not receive any input
    for tree in $trees/*.dot
    do
        name="${tree%.*}" #remove the .dot extension
	    dot -Tpng $tree -o "$user_desktop/TLSAssistant_report/${name##*/}.png"
    done
    echo "Attack trees rendered successfully!"
}

#START
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

if [[ "$1" -gt 2 ]]; then #if the user requested the highlighted trees
    cp $source_trees/* $trees/ #copy the sources to be edited
fi

while read entry; do #for each entry in the vulnerability list

    if [[ $entry != "webserver: "* ]];then #if the entry is not a webserver (which has already been handled)

        if [ -f "$mitigations/$entry".xml ]; then #if the file exists

            echo "## $(xmllint --xpath "/Entry/Name/text()" $mitigations/$entry.xml)" >> $report #write the name in the report
            echo "" >> $report

            collectDescription $entry #extract its description

            echo "#### Mitigation">> $report
            echo "" >> $report
            collectMitigation $entry #extract its mitigation
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
    fi
done < $vulnerabilityList

if [[ "$1" -gt 1 ]]; then #move the internal reports
    exportReports
fi

if [[ "$1" -gt 2 ]]; then #generate the highlighted trees
    generateTrees
fi

bash $root_folder/../utility/markdown.sh $report > $user_desktop/TLSAssistant_report/Report.html #convert to HTML
rm $report

echo
echo -e "\033[1mReport successfully generated!\033[0m"