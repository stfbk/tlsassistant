import json
import os
import shutil
import tarfile
import time

import requests

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
        files = ["t1_lib.c", "ssl_local.h", "s3_lib.c", "s2_lib.c", "ssl.h", "ssl_ciph.c", "ssl_locl.h", "ssl3.h",
                 "tls1.h", "ssl.h.in"]
        for file in files:
            if not os.path.exists(f"tmp/{release}/{file}"):
                extract_file(release, file)
            if file == "ssl.h.in" and os.path.exists(f"tmp/{release}/{file}"):
                shutil.move(f"tmp/{release}/{file}", f"tmp/{release}/ssl.h")
        if os.path.isdir(f"tmp/{release}/ssl"):
            shutil.rmtree(f"tmp/{release}/ssl")


def extract_file(release, file):
    tar = tarfile.open(f"tmp/{release}.tar.gz")
    first_name = tar.getnames()[0]
    if "/" in first_name:
        first_name = first_name.split("/")[0]
    names = tar.getnames()
    member_string = f"{first_name}/ssl/{file}"
    if member_string not in names:
        member_string = f"{first_name}/include/openssl/{file}"
    if member_string in names and not os.path.exists(f"tmp/{release}/{file}"):
        obj = tar.getmember(member_string)
        tar.extract(obj, path=f"tmp/")
        tar.close()
        if not os.path.isdir(f"tmp/{release}"):
            os.mkdir(f"tmp/{release}")
        shutil.move("tmp/" + member_string, f"tmp/{release}/{file}")
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
    with open("../configs/compliance/groups_defaults.json", "w") as f:
        json.dump(groups_dict, f, indent=4, sort_keys=True)


def extract_sigalgs(releases_data):
    sigalgs_dict = {}
    sigalgs_table = {}
    for release in releases_data:
        print(release)
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
                        i = 0
                        while line:
                            i += 1
                            line = f.readline()
                            if tlsext in line:
                                line = line.strip()
                                if "0x" in line:
                                    try:
                                        sigalgs_table[name] = "0x" + line.split("0x")[1]
                                    except IndexError:
                                        print("Error: ", line, release, name, tlsext, i)
                                        input()
                                elif "_name" in line:
                                    sigalgs_table[name] = line.split(" ")[-1].strip("\"")

        release = release.lower().replace("openssl", "")[1:]
        sigalgs_dict[release] = sigalgs
    # switch the keys and the values in sigalgs_table
    sigalgs_table = {v: k for k, v in [(x,y) for x,y in sigalgs_table.items() if "0x" in y]}
    sigalgs_name_mapping = {v: k for k, v in [(x,y) for x,y in sigalgs_table.items() if "0x" not in y]}
    for sigalg in sigalgs_table:
        pass
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
    iana_to_ietf.pop("NULL", None)
    with open("../configs/compliance/sigalgs.json", "w") as f:
        json.dump(sigalgs_dict, f, indent=4, sort_keys=True)
    with open("../configs/compliance/sigalgs_table.json", "w") as f:
        json.dump(sigalgs_table, f, indent=4, sort_keys=True)
    with open("../configs/compliance/sigalgs_iana_to_ietf.json", "w") as f:
        json.dump(iana_to_ietf, f, indent=4, sort_keys=True)


def get_ciphersuites_mapping(release):
    ciphersuites_mapping = {}
    lines = []
    valid_tokens = ["SSL3_TXT", "TLS1_TXT", "TLS1_3_RFC"]
    for file in ["ssl3.h", "tls1.h"]:
        with open(f"tmp/{release}/{file}", "r") as f:
            data = f.read()
            lines += data.split("\n")
    for line in lines:
        if any(valid_token in line for valid_token in valid_tokens):
            tokens = line.split(" ")
            tokens = [t.strip() for t in tokens if t.strip()]
            macro_name = ""
            cipher_string = ""
            for token in tokens:
                if any(valid_token in token for valid_token in valid_tokens):
                    macro_name = token.strip()
                elif "\"" in token:
                    cipher_string = token.strip("\"")
            if macro_name and cipher_string:
                ciphersuites_mapping[macro_name] = cipher_string
    return ciphersuites_mapping


def get_tags_aliases_mapping(release):
    file = "ssl_local.h" if os.path.isfile(f"tmp/{release}/ssl_local.h") else "ssl_locl.h"
    tags_mapping = {}
    with open(f"tmp/{release}/{file}", "r") as f:
        line = "a"
        while line:
            line = f.readline()
            if "SSL_" in line and "define" in line:
                tokens = line.split("define")
                tokens = [t.strip() for t in tokens if t.strip()]
                if len(tokens) > 1:
                    tokens = tokens[1].split()
                    if len(tokens) > 1:
                        tag = tokens[0]
                        value = tokens[1]
                        # We only need the tags that are not defined as hex values
                        # like PSK that becomes (SSL_kPSK | SSL_kRSAPSK | SSL_kECDHEPSK | SSL_kDHEPSK)
                        if "0x" not in value:
                            tags_mapping[tag] = value
    return tags_mapping


def get_tags_mapping(release):
    tags_mapping = {}
    with open(f"tmp/{release}/ssl.h", "r") as f:
        line = "a"
        while line:
            line = f.readline()
            if "SSL_TXT_" in line and "define" in line:
                tokens = line.split("define")
                if "/" in tokens[1]:
                    tokens[1] = tokens[1].split("/")[0]
                tokens = tokens[1].split()
                tokens = [t.strip() for t in tokens if t.strip()]
                tags_mapping[tokens[0].strip()] = tokens[1].strip().strip("\"")
    return tags_mapping


def update_ciphersuites_struct(release, dictionary, dictionary_mapping):
    tmp = {}
    if release.startswith("0.9"):
        for tag in dictionary:
            algs = dictionary[tag].pop("algorithms", "")
            if algs:
                algs = algs.split("|")
                to_insert = ["algorithm_mkey", "algorithm_auth", "algorithm_enc", "algorithm_mac",
                             "algorithm_ssl"]
                for alg in algs:
                    dictionary[tag][to_insert.pop(0)] = alg
    for tag in dictionary:
        if dictionary[tag].get("*name"):
            name = dictionary_mapping.get(dictionary[tag]["*name"], dictionary[tag]["*name"])
            name = name.strip("\"")
            tmp[name] = dictionary[tag]
            del tmp[name]["*name"]
        elif not isinstance(tag, int):
            tmp[tag] = dictionary[tag]
    return tmp


def get_counter_to_field(path, final_ciphers, release):
    counter_to_field = {}
    with open(path, "r") as f:
        line = "a"
        start = False
        counter = 0
        tls_1_2 = ""
        tls_1_3 = ""
        while line:
            line = f.readline()
            if "SSL_DEFAULT_CIPHER_LIST" in line:
                default_ciphers = line.split("\"")[1].strip("\"")
                tls_1_2 = default_ciphers
            elif "TLS_DEFAULT_CIPHERSUITES" in line:
                while "\\" in line:
                    default_ciphers = line.split("\"")[1].strip("\"")
                    tls_1_3 += default_ciphers
                    line = f.readline()
            if "ssl_cipher_st" in line and "SSL_CIPHER" not in line:
                start = True
            elif "};" in line or (start and "SSL_CIPHER;" in line):
                line = None
            elif start and ";" in line:
                field_name = line.split(";")[0].strip().split(" ")[-1]
                counter_to_field[counter] = field_name
                counter += 1
    actual_data = final_ciphers["releases_default"].get(release, "")
    if tls_1_3 and (isinstance(actual_data, str) or not actual_data):
        tls_1_2 = tls_1_2 if tls_1_2 else actual_data
        final_ciphers["releases_default"][release] = (tls_1_2, tls_1_3)
    elif tls_1_2 and not actual_data:
        final_ciphers["releases_default"][release] = tls_1_2
    elif tls_1_2 and isinstance(actual_data, tuple):
        final_ciphers["releases_default"][release] = (tls_1_2, actual_data[1])
    return counter_to_field


def get_actual_text(line, counter, counter_to_field, count, dictionary):
    line = line.split("/*")[0] if "/*" in line else line
    content = line.split(",") if line.count(",") > 1 else [line]
    content = [c.strip().strip(",") for c in content if c.strip().strip(",")]
    for i in range(0, len(content)):
        content[i] = content[i].strip("{").strip("}")
        dictionary[count][counter_to_field[counter]] = content[i]
        counter += 1
    return counter


def prune_tags_mapping(mapping):
    to_remove = []
    for version in mapping:
        for tag in mapping[version]:
            for field in mapping[version][tag]:
                if mapping[version][tag][field] in ["0", "NULL", ""]:
                    to_remove.append((version, tag, field))
    for version, tag, field in to_remove:
        del mapping[version][tag][field]
    to_remove = []
    for version in mapping:
        for tag in mapping[version]:
            if not mapping[version][tag]:
                to_remove.append(version, tag)
    for version, tag in to_remove:
        del mapping[version, tag]

def extract_ciphersuites_tags():
    final_tags_aliases = {}
    final_ciphers = {
        "releases_default": {},
        "ciphers_per_release": {}
    }
    releases_list = [r for r in os.listdir("tmp") if r[-2:] != "gz" and r[-3:] != "csv"]
    releases_list.sort()
    ciphersuites_mapping = get_ciphersuites_mapping(releases_list[-1])
    for release in releases_list:
        release = release.lower().replace("openssl", "")[1:]
        final_ciphers["ciphers_per_release"][release] = []
    for release in releases_list:
        tags_mapping = get_tags_mapping(release)
        file_release = release
        release = release.lower().replace("openssl", "")[1:]
        print("Release: ", release)
        counter_to_field = {}
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
                if tls1_2_ciphers and tls1_3_ciphers:
                    final_ciphers["releases_default"][release] = (tls1_2_ciphers, tls1_3_ciphers)

        file = "ssl.h"
        if os.path.exists(f"tmp/{file_release}/{file}"):
            path = f"tmp/{file_release}/{file}"
            counter_to_field = get_counter_to_field(path, final_ciphers, release)
        file = "ssl_local.h" if os.path.isfile(f"tmp/{file_release}/ssl_local.h") else "ssl_locl.h"
        if not counter_to_field and os.path.exists(f"tmp/{file_release}/{file}"):
            path = f"tmp/{file_release}/{file}"
            counter_to_field = get_counter_to_field(path, final_ciphers, release)
        if os.path.isfile(f"tmp/{file_release}/ssl_ciph.c"):
            alias_mapping = {}
            with open(f"tmp/{file_release}/ssl_ciph.c", "r") as f:
                line = "a"
                start = 0
                counter = 0
                while line:
                    line = f.readline()
                    if "SSL_CIPHER cipher_aliases" in line:
                        start = 1
                        counter = 0
                        tags_count = 0
                    elif start and "};" in line:
                        start = 0
                        line = None
                    elif start and ("{" in line or "}" in line):
                        if alias_mapping.get(tags_count) is None:
                            alias_mapping[tags_count] = {}
                            counter = 0
                        if counter_to_field.get(counter):
                            counter = get_actual_text(line, counter, counter_to_field, tags_count, alias_mapping)
                        else:
                            print("Error: ", line, file, release, counter_to_field, counter)
                            input()
                        if "}" in line:
                            tags_count += 1
            alias_mapping = update_ciphersuites_struct(release, alias_mapping, tags_mapping)
            for tag in alias_mapping:
                differences = {}
                category = release[:2]
                tags_to_remove = ["*stdname", "max_tls", "min_dtls", "max_dtls", "mask", "mask_strength", "id", "valid"]
                for tmp in tags_to_remove:
                    alias_mapping[tag].pop(tmp, None)
                if not final_tags_aliases.get(category):
                    final_tags_aliases[category] = {}
                if not final_tags_aliases[category].get(tag):
                    final_tags_aliases[category][tag] = alias_mapping[tag]
                    final_tags_aliases[category][tag]["releases"] = {}
                else:
                    for field in alias_mapping[tag]:
                        if field not in final_tags_aliases[category][tag]:
                            differences[field] = alias_mapping[tag][field]
                        elif (field != "releases" and final_tags_aliases[category][tag][field].replace(" ", "") !=
                              alias_mapping[tag][field].replace(" ", "")):
                            differences[field] = alias_mapping[tag][field]
                final_tags_aliases[category][tag]["releases"][release] = differences if differences else True

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
                                counter = get_actual_text(line, counter, counter_to_field, ciphers_counter, ciphers)
                            else:
                                print("Error: ", line_counter, line, file, release, counter_to_field, counter)
                                input()
                        elif "{" in line:
                            read += 1
                            ciphers_counter += 1
                            ciphers[ciphers_counter] = {}
                # make the name field the new key for each element that has a number as its key
                ciphers = update_ciphersuites_struct(release, ciphers, ciphersuites_mapping)
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
    prune_tags_mapping(final_tags_aliases)
    with open("../configs/compliance/tags_mapping.json", "w") as f:
        json.dump(final_tags_aliases, f, indent=4)
    with open("../configs/compliance/ciphersuites_tags.json", "w") as f:
        json.dump(final_ciphers, f, indent=4)


if __name__ == "__main__":
    if not os.path.exists("tmp"):
        os.mkdir("tmp")
    # extract_files()
    extract_tables()
    extract_ciphersuites_tags()
