#!/bin/bash 

report=${1##*/} #remove the path value
report=${report%.*} #remove the extension
report="$report.md"

#~ Name
xmllint --xpath "/Entry/Name/text()" $1 >> $report
printf "\n\n" >> $report
#~ ExtendedName
xmllint --xpath "/Entry/ExtendedName/text()" $1 >> $report
printf "\n\n" >> $report
#~ Description
xmllint --xpath "/Entry/Description/text()" $1 >> $report
printf "\n\n" >> $report
#~ Mitigation
#~ Textual
xmllint --xpath "/Entry/Mitigation/Textual/text()" $1 >> $report
printf "\n\n" >> $report
#~ Snippet
#~ Apache
printf "APACHE\n" >> $report
xmllint --xpath "/Entry/Mitigation/Snippet/apache/text()" $1 >> $report
printf "\n\n" >> $report
#~ Nginx
printf "NGINX\n" >> $report
xmllint --xpath "/Entry/Mitigation/Snippet/nginx/text()" $1 >> $report
printf "\n\n" >> $report