from pprint import pprint
import json
import argparse
from argparse import RawTextHelpFormatter
from xml.dom import minidom
import os.path
from stix2 import CourseOfAction
from stix2 import Vulnerability
from stix2 import Relationship
from stix2 import Bundle
from stix2 import File, Directory
from pathlib import PurePath
###################################### IN CASO DI SCANSIONE ###################################################
from stix2 import Sighting
from stix2 import ObservedData
from datetime import datetime

parser = argparse.ArgumentParser(description='Process JSON.', formatter_class=RawTextHelpFormatter)
parser.add_argument('path', type=str, action='store',
                    help='Path of the file to parse')
parser.add_argument('-m', '--mitigations', type=str, action='store', default=None,
                    help='Specify the mitigation folder')
parser.add_argument('-b', '--beautify', action='store_true',
                    help='Beautify the output to HTML style.')
group = parser.add_mutually_exclusive_group()
verbosemode = parser.add_mutually_exclusive_group()
group.add_argument('-s', '--separator', type=str, action='store',
                   help='Separator of the vuln data.', default='\n')
group.add_argument('-l', '--oneline', action='store_true',
                   help='Print every vuln in one line.')
parser.add_argument('-nd', '--nodescription', action='store_true',
                    help='Remove the description(except for verbose -1 and 4).', default=False)
verbosemode.add_argument('-v', '--verbose', type=int, action="store", default=0,
                    help='Set a verbose level.\n-1 for JSON\n0 for critically+name\n1 for 0+description\n2 for 1+file and line\n3 for 2+code\n4 for all datas.')
verbosemode.add_argument('-q', '--quiet', action='store_true',
                   help='No stdout output.', default=False)
parser.add_argument('-x','--stix', type=str, action='store', default=None,
                    help='Specify the stix output folder')

args = parser.parse_args()
if args.oneline:
    args.separator = " "


def XML_parser(path, item):
    mydoc = minidom.parse(path)
    items = mydoc.getElementsByTagName(item)
    return [elem.firstChild.data for elem in items]


def get_mitigation(vuln_name):
    if args.mitigations is not None:
        path = f"{args.mitigations}/{vuln_name.upper().replace(' ', '_')}.xml"

        if os.path.exists(path):
            return XML_parser(path, 'Textual')[0]
    return ""


def stixer(vulns, path):
    for vuln in vulns:
        timestamp = datetime.now()
        vuln_name = vuln['name']
        vuln_description = vuln['description']
        if args.mitigations:
            mitigation_description = get_mitigation(vuln['name'])
        else:
            mitigation_description = ""
        snippet_android = vuln['code']
        coa_name = vuln_name + "_coa"
        file_path = PurePath(vuln['file'])
        target = f"{str(file_path)}:{vuln['line']}"

        coa = CourseOfAction(type="course-of-action", name=coa_name, description=mitigation_description,
                             x_actions=[{"mitigation_android": "No snippet avaliable"}], allow_custom=True)
        vuln = Vulnerability(type="vulnerability", name=vuln_name, description=vuln_description,
        vulnerable_snippet= snippet_android, allow_custom=True)
        mitigates = Relationship(coa, 'mitigates', vuln)

        observed_object = File(
            name=target
        )
    

        observed_data = ObservedData(first_observed=timestamp, last_observed=timestamp, number_observed=1,
                                     objects={0: observed_object})
        sight = Sighting(vuln, observed_data_refs=[observed_data])
        bundle = Bundle(coa, mitigates, vuln, sight, observed_data, observed_object)
        with open(f"{path}/{vuln_name}.json", "w") as f:
            f.write(str(bundle) + "\n")


def get_json(path):
    f = open(path, 'r')
    return json.load(f)


def filter(vuln):
    return vuln['file'].lower() != "androidmanifest.xml"


def beautifier(string: str, beautify: bool, heading=None, format=None, pre=False):
    if not beautify:
        return string
    header = ""
    endheader = ""
    formatter = ""
    endformatter = ""
    preattr = ""
    endpreattr = ""
    if pre:
        preattr = f"<pre>"
        endpreattr = f"</pre>"
    if heading is not None:
        header = f"<h{heading}>"
        endheader = f"</h{heading}>"
    if format is not None:
        formatter = f"<{format}>"
        endformatter = f"</{format}>"

    return f"{header}{preattr}{formatter}{string}{endformatter}{endpreattr}{endheader}"


def verb_formatter(vuln, verboselevel, beautify):
    vuln['criticality'] = vuln['criticality'].upper()
    if verboselevel == -1:
        return str(vuln)
    output = []
    if verboselevel >= 0:
        output.append(beautifier(f"{vuln['criticality']}: {vuln['name']}", beautify, heading=2))
    if verboselevel >= 1:
        if not args.nodescription:
            output.append(f"{args.separator}{beautifier(vuln['description'], beautify, format='i')}")
    if args.mitigations:
        mitigation = get_mitigation(vuln['name'])
        to_append = f"{args.separator}{beautifier('Mitigation', beautify, format='b')} {args.separator}{args.separator}{beautifier(mitigation, beautify, format='i')}"
        output.append(f"{to_append if mitigation != '' else mitigation}")
    if verboselevel >= 2:
        output.append(
            f"{args.separator}{beautifier('File', beautify, format='b')} {beautifier(vuln['file'], beautify, format='code')}:{beautifier(vuln['line'], beautify, format='code')}")
    if verboselevel == 3:
        output.append(
            f"{args.separator}{args.separator}{beautifier('Vulnerable Code', beautify, format='b')} \t{beautifier(vuln['code'], beautify, format='code', pre=True)}")
    if verboselevel >= 4:
        string = []
        for key, item in vuln.items():
            string.append(f"{key}: {item}")
        return f"{args.separator}".join(string)

    return f"{args.separator}".join(output)


def vuln_to_list(json):
    condition = [
        'criticals',
        'highs',
        'mediums',
        'lows',
        'warnings'
    ]
    output = []
    for key, vulns in json.items():
        if key in condition:
            for vuln in vulns:
                if filter(vuln): output.append(vuln)

    return output


def remove_manifest(report, verbose=0, beautify=False):
    vulnerabilities = []
    for vuln in report['criticals']:
        if filter(vuln):
            vulnerabilities.append(verb_formatter(vuln, verbose, beautify))
    for vuln in report['highs']:
        if filter(vuln):
            vulnerabilities.append(verb_formatter(vuln, verbose, beautify))
    for vuln in report['mediums']:
        if filter(vuln):
            vulnerabilities.append(verb_formatter(vuln, verbose, beautify))
    for vuln in report['lows']:
        if filter(vuln):
            vulnerabilities.append(verb_formatter(vuln, verbose, beautify))
    for vuln in report['warnings']:
        if filter(vuln):
            vulnerabilities.append(verb_formatter(vuln, verbose, beautify))
    return vulnerabilities


path = args.path
json = get_json(path)
if args.stix:
    stixer(vuln_to_list(json), args.stix)
if not args.quiet:
    data = remove_manifest(json, args.verbose, args.beautify)
    if len(data) == 0:
        print("SUPER didn't find any TLS/SSL related issue.")
    else:
        print(f"{args.separator}{args.separator}".join(data))
