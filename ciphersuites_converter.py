import json
import importlib
import os.path
import shutil

tls_table = importlib.import_module("dependencies.tls-table.tls-table")
data = tls_table.get_hex_values()

iana_to_openssl = {}
openssl_to_iana = {}
for cipher in data:
    iana_to_openssl[data[cipher]["IANA"]] = data[cipher]["OpenSSL"]
    openssl_to_iana[data[cipher]["OpenSSL"]] = data[cipher]["IANA"]
with  open("ciphersuites.json", "w") as f:
    json.dump(data, f, indent=4)
with open("iana_to_openssl.json", "w") as f:
    json.dump(iana_to_openssl, f, indent=4)
with open("openssl_to_iana.json", "w") as f:
    json.dump(openssl_to_iana, f, indent=4)

shutil.move("ciphersuites.json", os.path.join("configs/compliance/", "ciphersuites.json"))
shutil.move("iana_to_openssl.json", os.path.join("configs/compliance/", "iana_to_openssl.json"))
shutil.move("openssl_to_iana.json", os.path.join("configs/compliance/", "openssl_to_iana.json"))
