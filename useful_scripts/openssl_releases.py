import requests
import os
import tarfile
import shutil
import json
import time
releases = ["1.0.0", "1.0.1", "1.0.2", "1.1.0", "1.1.1", "3.0", "3.1", "3.2"]
# THIS SCRIPT IS USED TO DOWNLOAD THE OPENSSL RELEASES AND EXTRACT THE SIGALGS
# FROM THE SOURCE CODE. THE SIGALGS ARE THEN USED IN THE CONFIGURATION FILES
# FOR THE COMPLIANCE MODULE.
# THE SCRIPT IS NOT USED IN THE ACTUAL ANALYSIS.
def download_releases():
    if not os.path.exists("urls.json"):
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
                     old_releases[release].append(line.split(">")[1].split("<")[0])
            time.sleep(0.2)
        urls = {}
        for release in latest_releases:
            urls[release.strip(".tar.gz")] = f"https://www.openssl.org/source/{release}"
        for release in old_releases:
            for old_release in old_releases[release]:
                urls[old_release.strip(".tar.gz")] = f"https://www.openssl.org/source/old/{release}/{old_release}"
        with open("urls.json", "w") as f:
            json.dump(urls, f, indent=4)
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
        # unzip only the file from the tar ssl/ti_lib.c
        if not os.path.exists(f"tmp/{release}/t1_lib.c"):
            extract_file(release, "t1_lib.c")
        if not os.path.exists(f"tmp/{release}/ssl_local.h"):
            extract_file(release, "ssl_local.h")
        if os.path.isdir(f"tmp/{release}/ssl"):
            shutil.rmtree(f"tmp/{release}/ssl")


def extract_file(release, file):
    tar = tarfile.open(f"tmp/{release}.tar.gz")
    first_name = tar.getnames()[0]
    if f"{first_name}/ssl/{file}" in tar.getnames():
        first_name = first_name.split("/")[0] if "/" in first_name else first_name
        tar.extract(f"{first_name}/ssl/{file}", path=f"tmp/")
        tar.close()
        shutil.move(f"tmp/{first_name}/ssl/{file}", f"tmp/{release}/{file}")
        if first_name != release:
            if not os.path.exists(f"tmp/{release}"):
                os.mkdir(f"tmp/{release}")
            shutil.rmtree(f"tmp/{first_name}")

def extract_sigalgs():
    sigalgs_dict = {}
    sigalgs_table = {}
    for release in [r for r in os.listdir("tmp") if r[-2:] != "gz" and r[-3:] != "csv"]:
        lines = []
        print("Release: ", release)
        with open(f"tmp/{release}/t1_lib.c", "r") as f:
            line = "a"
            start_reading = False
            while line:
                line = f.readline()
                if "static const SIGALG_LOOKUP sigalg_lookup_tbl[]" in line:
                    start_reading = True
                elif "SIGALG_LOOKUP" in line:
                    start_reading = False
                elif start_reading:
                    lines.append(line)
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




if __name__ == "__main__":
    if not os.path.exists("tmp"):
        os.mkdir("tmp")
    download_releases()
    extract_sigalgs()
