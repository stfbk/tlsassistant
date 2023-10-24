from z3c.rml import rml2pdf
from report_data import data_hosts, data_module
from jinja2 import Environment, FileSystemLoader

import hashlib, time
last_hash = ""
last_hash2 = ""
with open("log.txt", "w") as f:
    f.write("")

while True:
    variables = {
        "version": "2.1"
    }
    fsl = FileSystemLoader(searchpath="./")
    env = Environment(loader=fsl)
    env.filters.pop('pprint', None)
    with open("modules_report.xml", "rb") as f:
        hash = hashlib.md5(f.read()).hexdigest()
    with open("hosts_report.xml", "rb") as f:
        hash2 = hashlib.md5(f.read()).hexdigest()
    if last_hash != hash:
        print("Hash changed, reloading")
        try:
            template = env.get_template("modules_report.xml")
        except Exception as e:
            print(e)
        with open("modules_report_complete.xml", "w") as f:
            try:
                f.write(template.render(**data_module))
            except Exception as e:
                print(e)
        try:
            rml2pdf.go('modules_report_complete.xml','file.pdf')
        except Exception as e:
            with open("log.txt", "a") as f:
                f.write(str(e))
                f.write("\n")
        last_hash = hash
    if last_hash2 != hash2:
        print("Hash changed, reloading 2")
        try:
            template = env.get_template("hosts_report.xml")
        except Exception as e:
            print(e)
        with open("hosts_report_complete.xml", "w") as f:
            try:
                f.write(template.render(**data_hosts))
            except Exception as e:
                print(e)
        try:
            rml2pdf.go('hosts_report_complete.xml','file_hosts.pdf')
        except Exception as e:
            with open("log.txt", "a") as f:
                f.write(str(e))
                f.write("\n")
        last_hash2 = hash2
    time.sleep(0.5)
    

