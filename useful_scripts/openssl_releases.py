import pprint

import requests
import os
import tarfile
import shutil
import json
import time
# dentro ssl/ssl.h c'è # define SSL_DEFAULT_CIPHER_LIST "ALL:!EXPORT:!aNULL:!eNULL:!SSLv2"
releases = ["0.9.x", "1.0.0", "1.0.1", "1.0.2", "1.1.0", "1.1.1", "3.0", "3.1", "3.2"]
# THIS SCRIPT IS USED TO DOWNLOAD THE OPENSSL RELEASES AND EXTRACT THE SIGALGS
# FROM THE SOURCE CODE. THE SIGALGS ARE THEN USED IN THE CONFIGURATION FILES
# FOR THE COMPLIANCE MODULE.
# THE SCRIPT IS NOT USED IN THE ACTUAL ANALYSIS.
def download_releases():
    # get the latest release
    r = requests.get("https://www.openssl.org/source/")
    lines = r.text.split("\n")
    latest_releases = []
    for line in lines:
        if "openssl-" in line and ".tar.gz" in line:
            latest_releases.append(line.split(">")[1].split("<")[0])
    old_releases = {}
    for release in releases:
        old_releases[release] = []
        r = requests.get(f"https://www.openssl.org/source/old/{release}/")
        lines = r.text.split("\n")
        for line in lines:
            if "openssl-" in line and ".tar.gz" in line:
                old_releases[release].append(line.split(">")[2].split("<")[0])
        time.sleep(0.2)
    urls = {}
    for release in latest_releases:
        urls[release.strip(".tar.gz")] = f"https://www.openssl.org/source/{release}"
    for release in old_releases:
        for old_release in old_releases[release]:
            urls[old_release.strip(".tar.gz")] = f"https://www.openssl.org/source/old/{release}/{old_release}"
    del urls[""]
    to_remove = []
    for release in urls:
        if "fips" in release or "engine" in release:
            to_remove.append(release)
    for release in to_remove:
        del urls[release]
    with open("urls.json", "w") as f:
        json.dump(urls, f, indent=4, sort_keys=True)
    return urls

def extract_files():
    if not os.path.exists("urls.json"):
        urls = download_releases()
    else:
        with open("urls.json", "r") as f:
            urls = json.load(f)
    for release in urls:
        print("Release: ", release)
        if not os.path.exists(f"tmp/{release}.tar.gz"):
            time.sleep(0.5)
            # download the file
            r = requests.get(urls[release])
            # write the file
            with open(f"tmp/{release}.tar.gz", "wb") as f:
                f.write(r.content)
        # unzip only the necessary files
        files = ["t1_lib.c", "ssl_local.h", "s3_lib.c", "s2_lib.c", "ssl.h", "ssl_ciph.c"]
        for file in files:
            if not os.path.exists(f"tmp/{release}/{file}"):
                extract_file(release, file)
        if os.path.isdir(f"tmp/{release}/ssl"):
            shutil.rmtree(f"tmp/{release}/ssl")


def extract_file(release, file):
    tar = tarfile.open(f"tmp/{release}.tar.gz")
    first_name = tar.getnames()[0]
    if "/" in first_name:
        first_name = first_name.split("/")[0]
    member_string = f"{first_name}/ssl/{file}"
    if member_string in tar.getnames():
        obj = tar.getmember(member_string)
        tar.extract(obj, path=f"tmp/")
        tar.close()
        if not os.path.isdir(f"tmp/{release}"):
            os.mkdir(f"tmp/{release}")
        shutil.move(f"tmp/{first_name}/ssl/{file}", f"tmp/{release}/{file}")
        if first_name != release:
            if not os.path.exists(f"tmp/{release}"):
                os.mkdir(f"tmp/{release}")
            shutil.rmtree(f"tmp/{first_name}")

def extract_tables():
    pairs = {
        "sigalg_lookup_tbl[]": {
            "end": "SIGALG_LOOKUP",
            "key": "sigalgs"
        },
        "supported_groups_default[]": {
            "end": "};",
            "key": "groups_default"
        },
        "eccurves_default[]": {
            "end": "};",
            "key": "groups_default"
        },
    }
    tables = {}
    for release in [r for r in os.listdir("tmp") if r[-2:] != "gz" and r[-3:] != "csv"]:
        print("Release: ", release)
        with open(f"tmp/{release}/t1_lib.c", "r") as f:
            tables[release] = {}
            line = "a"
            start_reading = False
            end = ""
            while line:
                line = f.readline()
                if not start_reading:
                    for key in pairs:
                        if key in line:
                            start_reading = pairs[key]["key"]
                            tables[release][start_reading] = []
                            end = pairs[key]["end"]
                elif end and end in line:
                    start_reading = False
                    end = ""
                elif start_reading:
                    tables[release][start_reading].append(line)
    extract_sigalgs(tables)
    extract_groups(tables)

def extract_groups(releases_data):
    groups_dict = {}
    for release in releases_data:
        lines = releases_data[release].get("groups_default", [])
        groups = []
        for l in lines:
            if "/*" in l:
                # remove also */ from the line
                l = l.split("/*")[1].strip()[:-2]
                if " " in l:
                    l = l.split(" ")[0]
                # Don't add gost groups because they are not enabled by default in openssl
                if not l.startswith("GC") and len(l) > 6:
                    groups.append(l)
        if not lines:
            groups = ["prime256v1"]
        release = release.lower().replace("openssl", "")[1:]
        groups_dict[release] = groups
    with open("../configs/compliance/groups.json", "w") as f:
        json.dump(groups_dict, f, indent=4, sort_keys=True)

def extract_sigalgs(releases_data):
    sigalgs_dict = {}
    sigalgs_table = {}
    print(releases_data.keys())
    for release in releases_data:
        lines = releases_data[release].get("sigalgs", [])
        sigalgs = []
        for l in lines:
            if "TLSEXT_SIGALG" in l and "gost" not in l:
                l = l.strip().strip("{").strip(",")
                name, tlsext = l.split(",")
                name = name.strip().strip("\"")
                if name != "NULL":
                    sigalgs.append(name)
                if name not in sigalgs_table and name != "NULL":
                    with open(f"tmp/{release}/ssl_local.h", "r") as f:
                        line = "a"
                        while line:
                            line = f.readline()
                            if tlsext in line:
                                line = line.strip()
                                sigalgs_table[name] = "0x" + line.split("0x")[1]

        release = release.lower().replace("openssl", "")[1:]
        sigalgs_dict[release] = sigalgs
    # switch the keys and the values in sigalgs_table
    sigalgs_table = {v: k for k, v in sigalgs_table.items()}
    if not os.path.exists("tmp/iana_sigalgs.csv"):
        r = requests.get("https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv")
        with open("tmp/iana_sigalgs.csv", "w") as f:
            f.write(r.text)
    with open("tmp/iana_sigalgs.csv", "r") as f:
        lines = f.readlines()
        lines = [l.strip().split(",") for l in lines]
        lines = lines[1:]
        tmp_dict = {}
        for l in lines:
            tmp_dict[l[0].lower()] = l[1]
        lines = tmp_dict
    for sigalg in sigalgs_table:
        sigalgs_table[sigalg] = {
            "ietf": sigalgs_table[sigalg],
            "iana": lines.get(sigalg, "NULL"),
        }
    iana_to_ietf = {}
    for sigalg in sigalgs_table:
        iana_to_ietf[sigalgs_table[sigalg]["iana"]] = sigalgs_table[sigalg]["ietf"]
    with open("../configs/compliance/sigalgs.json", "w") as f:
        json.dump(sigalgs_dict, f, indent=4, sort_keys=True)
    with open("../configs/compliance/sigalgs_table.json", "w") as f:
        json.dump(sigalgs_table, f, indent=4, sort_keys=True)
    with open("../configs/compliance/sigalgs_iana_to_ietf.json", "w") as f:
        json.dump(iana_to_ietf, f, indent=4, sort_keys=True)

def extract_ciphersuites_tags():
    final_ciphers = {
        "releases_default": {},
        "ciphers_per_release": {}
    }
    releases_list = [r for r in os.listdir("tmp") if r[-2:] != "gz" and r[-3:] != "csv"]
    releases_list.sort()
    for release in releases_list:
        release = release.lower().replace("openssl", "")[1:]
        final_ciphers["ciphers_per_release"][release] = []
    for release in releases_list:
        file_release = release
        release = release.lower().replace("openssl", "")[1:]
        print("Release: ", release)
        counter_to_field = {}
        # at the moment we consider only ciphersuites from openssl 1.0.0 onwards
        file = "ssl.h"
        if not os.path.exists(f"tmp/{file_release}/{file}"):
            file = "ssl_local.h"
        if os.path.exists(f"tmp/{file_release}/{file}"):
            with open(f"tmp/{file_release}/{file}", "r") as f:
                line = "a"
                start = False
                counter = 0
                while line:
                    line = f.readline()
                    if "SSL_DEFAULT_CIPHER_LIST" in line:
                        default_ciphers = line.split("\"")[1].strip("\"")
                        final_ciphers["releases_default"][release] = default_ciphers
                    if "ssl_cipher_st" in line and "SSL_CIPHER" not in line:
                        start = True
                    elif "};" in line or (start and "SSL_CIPHER;" in line):
                        line = None
                    elif start and ";" in line:
                        field_name = line.split(";")[0].strip().split(" ")[-1]
                        counter_to_field[counter] = field_name
                        counter += 1
        if not counter_to_field:
            values_to_add = ["valid", "*name", "id", "algorithm_mkey", "algorithm_auth", "algorithm_enc",
                             "algorithm_mac",
                             "min_tls", "max_tls", "min_dtls", "max_dtls", "algo_strength", "algorithm2",
                             "strength_bits", "alg_bits"]
            if release.startswith("1.1.1"):
                values_to_add.insert(2, "*stdname")
            elif release.startswith("1.1.0-pre"):
                values_to_add[7] = "algorithm_ssl"
                values_to_add.remove("max_tls")
                values_to_add.remove("min_dtls")
                values_to_add.remove("max_dtls")
            counter_to_field = {}
            for i, v in enumerate(values_to_add):
                counter_to_field[i] = v
        if not final_ciphers["releases_default"].get(release) and os.path.isfile(f"tmp/{file_release}/ssl_ciph.c"):
            with open(f"tmp/{file_release}/ssl_ciph.c", "r") as f:
                line = "a"
                start = 0
                tls1_2_ciphers = ""
                tls1_3_ciphers = ""
                while line:
                    line = f.readline()
                    if "OSSL_default_cipher_list" in line:
                        start = 1
                    elif "OSSL_default_ciphersuites" in line:
                        start = 2
                    elif start and "\"" in line:
                        if start == 1:
                            tls1_2_ciphers += line.split(" ")[-1].strip("\";\n")
                            start = 2
                        elif start == 2:
                            tls1_3_ciphers += line.split(" ")[-1].strip("\";\n")
                    elif start and "}" in line:
                        start = 0
                if not (tls1_2_ciphers and tls1_3_ciphers):
                    # If the ciphersuites are not defined in ssl_ciph.c, we use the default ones
                    final_ciphers["releases_default"][release] = "ALL:!aNULL:!eNULL"
                else:
                    final_ciphers["releases_default"][release] = (tls1_2_ciphers, tls1_3_ciphers)

        ciphers = {}
        for file in ["s2_lib.c", "s3_lib.c"]:
            line_counter = 0
            read = -1
            skipping = 0
            ciphers_counter = 0
            total_blocks = 1
            if os.path.isfile(f"tmp/{file_release}/{file}"):
                counter = 0
                with open(f"tmp/{file_release}/{file}", "r") as f:
                    line = "a"
                    while line:
                        line_counter += 1
                        line = f.readline()
                        if "tls13_ciphers" in line:
                            total_blocks += 1
                        if "downgrade" in line and read == -1:
                            continue
                        if "if 0" in line:
                            skipping += 1
                        elif skipping > 1 and "endif" in line:
                            skipping -= 1
                        elif skipping > 1 and "if" in line:
                            skipping += 1

                        elif "}" in line and read != -1:
                            read = 0
                            counter = 0
                            # the list of ciphersuites is over
                            if "};" in line:
                                total_blocks -= 1
                                read = -1
                                if total_blocks == 0:
                                    line = None
                        elif read > 0 and skipping == 0:
                            if counter_to_field.get(counter):
                                line = line.split("/*")[0] if "/*" in line else line
                                content = line.split(",") if line.count(",") > 1 else [line]
                                content = [c.strip().strip(",") for c in content if c.strip().strip(",")]
                                ciphers[ciphers_counter][counter_to_field[counter]] = content[0]
                                i = 0
                                if len(content) > 1:
                                    i += 1
                                    counter += 1
                                    ciphers[ciphers_counter][counter_to_field[counter]] = content[i]
                            else:
                                print("Error: ", line_counter, line, file, release, counter_to_field, counter)
                                input()
                            counter += 1
                        elif "{" in line:
                            read += 1
                            ciphers_counter += 1
                            ciphers[ciphers_counter] = {}
                # make the name field the new key for each element that has a number as its key
                tmp = {}
                if release.startswith("0.9"):
                    for cipher in ciphers:
                        algs = ciphers[cipher].pop("algorithms", "")
                        if algs:
                            algs = algs.split("|")
                            to_insert = ["algorithm_mkey", "algorithm_auth", "algorithm_enc", "algorithm_mac",
                                         "algorithm_ssl"]
                            for alg in algs:
                                ciphers[cipher][to_insert.pop(0)] = alg
                for cipher in ciphers:
                    if ciphers[cipher].get("*name"):
                        tmp[ciphers[cipher]["*name"]] = ciphers[cipher]
                        del tmp[ciphers[cipher]["*name"]]["*name"]
                    elif not isinstance(cipher, int):
                        tmp[cipher] = ciphers[cipher]
                ciphers = tmp
        for cipher in ciphers:
            differences = {}
            if not final_ciphers.get(cipher):
                final_ciphers[cipher] = ciphers[cipher]
                final_ciphers[cipher]["releases"] = {}
            else:
                for field in ciphers[cipher]:
                    if field not in final_ciphers[cipher]:
                        final_ciphers[cipher][field] = ciphers[cipher][field]
                    elif field != "releases" and field != "source" and \
                            final_ciphers[cipher][field].replace(" ", "") != ciphers[cipher][field].replace(" ", ""):
                        differences[field] = ciphers[cipher][field]
            final_ciphers[cipher]["releases"][release] = differences if differences else True
            final_ciphers["ciphers_per_release"][release].append(cipher)


    with open("../configs/compliance/ciphersuites_tags.json", "w") as f:
        json.dump(final_ciphers, f, indent=4)





if __name__ == "__main__":
    if not os.path.exists("tmp"):
        os.mkdir("tmp")
    #extract_files()
    extract_tables()
    extract_ciphersuites_tags()