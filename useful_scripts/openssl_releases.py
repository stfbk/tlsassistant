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
        tar = tarfile.open(f"tmp/{release}.tar.gz")
        first_name = tar.getnames()[0]
        first_name = first_name.split("/")[0] if "/" in first_name else first_name
        tar.extract(f"{first_name}/ssl/t1_lib.c", path=f"tmp/")
        tar.close()
        shutil.move(f"tmp/{first_name}/ssl/t1_lib.c", f"tmp/{release}/t1_lib.c")
        if first_name != release:
            if not os.path.exists(f"tmp/{release}"):
                os.mkdir(f"tmp/{release}")
            shutil.rmtree(f"tmp/{first_name}")

def extract_sigalgs():
    sigalgs_dict = {}
    for release in [r for r in os.listdir("tmp") if r[-2:] != "gz"]:
        lines = []
        print("Release: ", release)
        with open(f"tmp/{release}/t1_lib.c", "r") as f:
            line = "a"
            start_reading = False
            while line:
                line = f.readline()
                if "/* Default sigalg schemes */" in line:
                    start_reading = True
                if "SIGALG_LOOKUP" in line:
                    start_reading = False
                if start_reading:
                    lines.append(line)
        sigalgs = []
        for l in lines:
            if "TLSEXT_SIGALG" in l and "gost" not in l:
                l = l.strip().strip(",").strip("TLSEXT_SIGALG_")
                sigalgs.append(l)
        release = release.lower().replace("openssl", "")[1:]
        sigalgs_dict[release] = sigalgs
    with open("../configs/compliance/sigalgs.json", "w") as f:
        json.dump(sigalgs_dict, f, indent=4, sort_keys=True)




if __name__ == "__main__":
    if not os.path.exists("tmp"):
        os.mkdir("tmp")
    download_releases()
    extract_sigalgs()
