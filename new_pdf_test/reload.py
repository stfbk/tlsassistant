from z3c.rml import rml2pdf
from report_data import data_hosts, data_module
from jinja2 import Environment, FileSystemLoader
import re
import hashlib, time, json

last_hash = ""
last_hash2 = ""
with open("log.txt", "w") as f:
    f.write("")

replacements = {
    'sub': re.sub,
    "Replacements": {
        "(<a href=.*?</a>)": "<font color='blue'>\\1</font>",
        "<code>(.*?)</code>": "<font color='#d63384' fontName='Roboto Italic'>\\1</font>",
    }
}
with open("../configs/module_to_mitigation.json", "r") as f:
    files = json.load(f)
replacements["name_mapping"] = {}

for module in files:
    with open("../configs/mitigations/" + files[module], "r") as f:
        data = json.load(f)
    replacements["name_mapping"][module] = data.get("Entry", {}).get("Name", "Unknown")
while True:
    variables = {"version": "2.1"}
    fsl = FileSystemLoader(searchpath="./")
    env = Environment(loader=fsl)
    with open("modules_report_test.xml", "rb") as f:
        hash = hashlib.md5(f.read()).hexdigest()
    with open("hosts_report_test.xml", "rb") as f:
        hash2 = hashlib.md5(f.read()).hexdigest()
    if last_hash != hash:
        data = {**replacements, **data_module}
        print("Hash changed, reloading by-module")
        try:
            template = env.get_template("modules_report_test.xml")

            with open("modules_report_complete.xml", "w") as f:
                f.write(template.render(**data))
        except Exception as e:
            print(e)
        try:
            rml2pdf.go("modules_report_complete.xml", "file.pdf")
        except Exception as e:
            with open("log.txt", "a") as f:
                f.write(str(e))
                f.write("\n")
        last_hash = hash
    if last_hash2 != hash2:
        print("Hash changed, reloading by-host")
        data = {**replacements, **data_hosts}
        try:
            template = env.get_template("hosts_report_test.xml")
        except Exception as e:
            with open("log.txt", "a") as f:
                f.write(str(e))
                f.write("\n")
        with open("hosts_report_complete.xml", "w") as f:
            try:
                f.write(template.render(**data))
            except Exception as e:
                print("rendering exception", e)
        try:
            rml2pdf.go("hosts_report_complete.xml", "file_hosts.pdf")
        except Exception as e:
            with open("log.txt", "a") as f:
                f.write(str(e))
                f.write("\n")
        last_hash2 = hash2
    time.sleep(0.5)
