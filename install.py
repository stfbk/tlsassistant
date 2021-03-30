import asyncio
import json
import sys

import aiohttp
import async_timeout
from zipfile import ZipFile
from os import path, geteuid, mkdir, sep, remove, devnull
import subprocess
import argparse
import logging
from shutil import rmtree as rm_rf

parser = argparse.ArgumentParser(description="Installer for TLSAssistant")
parser.add_argument("-v", "--verbose", help="Verbose mode.", action="store_true")

args = parser.parse_args()

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)


class Install:
    def __init__(self, dependencies):
        gits = []
        pkgs = []
        zips = []
        logging.info("Loading dependencies...")
        for dependency in dependencies:
            if dependency["type"] == "git":
                gits.append(dependency["url"])
                logging.debug(f"Added dependency git {dependency['url']}")
            elif dependency["type"] == "pkg":
                pkgs.append(dependency["url"])
                logging.debug(f"Added dependency pkg {dependency['url']}")
            elif dependency["type"] == "zip":
                zips.append(dependency["url"])
                logging.debug(f"Added dependency zip {dependency['url']}")
            else:
                logging.warning(
                    f"Ignoring dependency {dependency['url']}, type {dependency['type']} is not recognized."
                )
        logging.info("Getting files...")
        logging.debug("Getting all pkgs...")
        loop = asyncio.get_event_loop()
        results_pkgs = loop.run_until_complete(self.download(pkgs))
        logging.debug(results_pkgs)
        logging.debug("Getting all zips...")
        loop = asyncio.get_event_loop()
        results_zips = loop.run_until_complete(self.download(zips))
        logging.debug(results_zips)
        logging.debug("Getting all git...")
        for git in gits:
            file_name = self.get_filename(git)
            logging.info(f"getting {file_name}...")
            self.git_clone(git)
            logging.info(f"{file_name} done.")

        logging.info("Installing dependencies...")
        self.install_dependencies('pkgs', results_pkgs)
        logging.info("Unzipping dependencies...")
        self.install_dependencies('zips', results_zips)
        logging.info("All done!")

    def install_dependencies(self, type, results):

        for file in results:
            if type == 'pkgs':
                logging.debug(f"Installing dependencies{sep}{file}")
                with open(devnull, 'w') as null:
                    subprocess.check_call(
                        ["sudo", "apt-get", "install", "-y", f"./dependencies{sep}{file}"],
                        stderr=sys.stderr,
                        stdout=(
                            sys.stdout
                            if logging.getLogger().isEnabledFor(logging.DEBUG)
                            else null
                        ),
                    )
            elif type == 'zips':
                logging.debug(f"Unzipping dependencies{sep}{file}")
                with ZipFile(f"dependencies{sep}{file}", 'r') as zip:
                    zip.extractall(f"dependencies{sep}{file.rsplit('.', 1)[0]}")
            else:
                logging.error('no type found.')
                raise AssertionError("The type given doesn't match one of the existing one.")
            if path.exists(f"dependencies{sep}{file}"):
                logging.debug(f"Removing file dependencies{sep}{file}")
                remove(f"dependencies{sep}{file}")

    def git_clone(self, url, path=None):
        file_name = self.get_filename(url)
        with open(devnull, 'w') as null:
            subprocess.call(
                [
                    "git",
                    "clone",
                    str(url),
                    f"{path if path else 'dependencies' + sep + file_name}",
                ],
                stderr=sys.stderr if logging.getLogger().isEnabledFor(logging.DEBUG) else null,
                stdout=(
                    sys.stdout if logging.getLogger().isEnabledFor(logging.DEBUG) else null
                ),
            )

    async def get_url(self, url, session):

        file_name = self.get_filename(url)

        async with async_timeout.timeout(60):
            async with session.get(url) as response:
                with open(f"dependencies{sep}{file_name}", "wb") as fd:
                    async for data in response.content.iter_chunked(1024):
                        fd.write(data)
                        # logging.debug(f"Downloaded {url} in {file_name}")
        return file_name

    async def download(self, urls):
        async with aiohttp.ClientSession() as session:
            tasks = [self.get_url(url, session) for url in urls]

            return await asyncio.gather(*tasks)

    def get_filename(self, url):
        fragment_removed = url.split("#")[0]
        query_string_removed = fragment_removed.split("?")[0]
        scheme_removed = query_string_removed.split("://")[-1].split(":")[-1]

        if scheme_removed.find("/") == -1:
            return ""
        return path.basename(scheme_removed)


def main():  # exec main
    if not path.exists("dependencies"):
        logging.debug("Folder dependencies does not exist. Creating a new one.")
    else:
        logging.debug("Folder dependencies exist. Removing and creating a new one.")
        rm_rf("dependencies")
    mkdir("dependencies")
    if path.exists("dependencies.json"):
        with open("dependencies.json", "r") as dep:  # load dependencies
            data = dep.read()
            dependencies = json.loads(data)
            Install(dependencies)  # install dependencies
    else:
        logging.error("File not found, dependency links are missing. Abort.")
        raise FileNotFoundError("File dependencies is not found, Abort.")


if __name__ == "__main__":
    if geteuid() == 0:  # check if sudo
        main()
    else:
        logging.warning("This tools need SUDO to work.")
        subprocess.check_call(["sudo", sys.executable] + sys.argv)  # force sudo
