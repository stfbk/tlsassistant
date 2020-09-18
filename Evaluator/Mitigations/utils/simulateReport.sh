#!/bin/bash 
if [[ $# -lt 1 ]] ; then #if help requested (or not enough parameters)
    echo "Usage: \"bash simulateReport.sh <vulnerability>.xml\""
    exit
fi

report=${1##*/} #remove the path value
report=${report%.*} #remove the extension
report="$report.md"

#~ Name
printf "## " >> $report
xmllint --xpath "/Entry/Name/text()" $1 >> $report
printf "\n\n" >> $report

#~ ExtendedName
printf "Extended name: " >> $report
xmllint --xpath "/Entry/ExtendedName/text()" $1 >> $report
printf "\n\n" >> $report

#~ Description
xmllint --xpath "/Entry/Description/text()" $1 >> $report
printf "\n\n" >> $report

#~ CVE
printf "CVE: " >> $report
xmllint --xpath "/Entry/CVE/text()" $1 >> $report
printf "\n\n" >> $report

#~ CVSS
printf "CVSSv" >> $report
vuln_cvss=$(xmllint --xpath "/Entry/CVSS3/text()" $1 2>&1)
if [ "$vuln_cvss" = "XPath set is empty" ]; then #if CVSSv3 score is not available
    vuln_cvss=$(xmllint --xpath "/Entry/CVSS2/text()" $1 2>&1)
    printf "2 score:" >> $report
else
    printf "3 score:" >> $report
fi
printf $vuln_cvss >> $report
printf "\n\n" >> $report

#~ Mitigation
#~ Textual
printf "#### Mitigation\n" >> $report
xmllint --xpath "/Entry/Mitigation/Textual/text()" $1 >> $report
printf "\n\n" >> $report

#~ Snippet
#~ Apache
printf "##### APACHE\n" >> $report
xmllint --xpath "/Entry/Mitigation/Snippet/apache/text()" $1 >> $report
printf "\n\n" >> $report

#~ Nginx
printf "##### NGINX\n" >> $report
xmllint --xpath "/Entry/Mitigation/Snippet/nginx/text()" $1 >> $report
printf "\n\n" >> $report

echo -e "Report saved in $(pwd)"