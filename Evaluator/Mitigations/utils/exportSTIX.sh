#!/bin/bash
root_folder="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [[ ! -d $root_folder/../../../python_dep ]]; then #if the INSTALLER has never been called
    echo "Run INSTALL.sh to setup the environment first"
    exit 1
fi
exporter=$root_folder/exporter.py
mkdir -p $root_folder/../STIX
IFS='"' #internal field separator - used to escape the double quotes

#report content
vuln_name=""
vuln_description=""
mitigation_description=""
snippet_apache=""
snippet_nginx=""

# python wrapping (modules and lists)
echo "# encoding=utf8" >> $exporter
echo "from stix2 import CourseOfAction" >> $exporter
echo "from stix2 import Vulnerability " >> $exporter
echo "from stix2 import Relationship" >> $exporter
echo "from stix2 import Bundle" >> $exporter
echo "coa=[]" >> $exporter
echo "vuln=[]" >> $exporter
echo "mitigates=[]" >> $exporter

for entry in $root_folder/../*.xml #for each available entry
do
    # values extraction
    vuln_name=$(xmllint --xpath "/Entry/Name/text()" $entry 2>&1)
    vuln_description=$(xmllint --xpath "/Entry/Description/text()" $entry 2>&1)
    mitigation_description=$(xmllint --xpath "/Entry/Mitigation/Textual/text()" $entry 2>&1)
    snippet_apache=$(xmllint --xpath "/Entry/Mitigation/Snippet/apache/text()" $entry 2>&1)
    snippet_nginx=$(xmllint --xpath "/Entry/Mitigation/Snippet/nginx/text()" $entry 2>&1)

    #values formatting (removing the newline control character)
    vuln_name=$(echo $vuln_name|tr -d '\n')
    vuln_description=$(echo $vuln_description|tr -d '\n')
    mitigation_description=$(echo $mitigation_description|tr -d '\n')
    snippet_apache=$(echo $snippet_apache|tr -d '\n')
    snippet_nginx=$(echo $snippet_nginx|tr -d '\n')
    coa_name=$(echo $vuln_name"_coa")

    # double quotes escaping
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

    # python wrapping (structures creation)
    echo "coa.append(CourseOfAction(type=\"course-of-action\",name=\"$coa_name\",description=\"$mitigation_description\",x_actions=[{\"mitigation_apache\":\"${snippet_apache::-1}\",\"mitigation_nginx\":\"${snippet_nginx::-1}\"}], allow_custom=True))" >> $exporter #::-1 because the last character is an extra '
    echo "vuln.append(Vulnerability(type=\"vulnerability\",name=\"$vuln_name\",description=\"$vuln_description\"))" >> $exporter
    echo "mitigates.append(Relationship(coa[-1], 'mitigates', vuln[-1]))" >> $exporter

done

# python wrapping (json generation)
echo "for i in range(0, len(coa)):" >> $exporter
echo "    bundle = Bundle(coa[i], mitigates[i], vuln[i])" >> $exporter
echo "    filename=\"$root_folder/../STIX/\"+vuln[i]['name']+\".json\"" >> $exporter
echo "    f = open(filename, \"w\")" >> $exporter
echo "    f.write(str(bundle)+\"\n\")" >> $exporter
echo "    f.close()" >> $exporter

$root_folder/../../../python_dep/bin/python $exporter
rm $exporter
