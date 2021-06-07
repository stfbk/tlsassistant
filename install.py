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

# parser for the arguments
parser = argparse.ArgumentParser(
    description="Installer for TLSAssistant"
)  # todo: edit the description of the tool
parser.add_argument(
    "-v", "--verbose", help="Verbose mode.", action="store_true"
)  # verbose flag

args = parser.parse_args()  # parse arguments

if args.verbose:  # if verbose is set
    logging.basicConfig(level=logging.DEBUG)  # logger is set to debug
else:
    logging.basicConfig(level=logging.INFO)  # logger is set to info


class Install:
    def __init__(self, dependencies):  # constructor
        gits = []
        pkgs = []
        zips = []
        cfgs = []
        apts = []
        logging.info("Loading dependencies...")
        for dependency in dependencies:  # for each dependency
            if dependency["type"] == "git":  # if it's git
                gits.append(dependency["url"])  # append it's url to the git array
                logging.debug(f"Added dependency git {dependency['url']}")
            elif dependency["type"] == "pkg":  # if it's pkg
                pkgs.append(dependency["url"])  # append it's url to the pkg array
                logging.debug(f"Added dependency pkg {dependency['url']}")
            elif dependency["type"] == "apt":  # if it's zip
                apts.append(dependency["url"])  # append it's url to the zip array
                logging.debug(f"Added dependency apt {dependency['url']}")
            elif dependency["type"] == "zip":  # if it's zip
                zips.append(dependency["url"])  # append it's url to the zip array
                logging.debug(f"Added dependency zip {dependency['url']}")
            elif dependency["type"] == "cfg":  # if it's cfg
                cfgs.append(dependency["url"])  # append it's url to the cfg array
                logging.debug(f"Added dependency cfg {dependency['url']}")
            else:  # if not found, throw warning
                logging.warning(
                    f"Ignoring dependency {dependency['url']}, type {dependency['type']} is not recognized."
                )
        logging.info("Getting files...")
        logging.debug("Getting all cfgs...")
        loop = asyncio.get_event_loop()
        results_apts = apts
        results_cfgs = loop.run_until_complete(self.download(cfgs))
        logging.debug(results_cfgs)
        logging.debug("Getting all pkgs...")
        loop = asyncio.get_event_loop()  # asnychronous event loop
        results_pkgs = loop.run_until_complete(
            self.download(pkgs)
        )  # download asynchronously all the files
        logging.debug(results_pkgs)
        logging.debug("Getting all zips...")
        loop = asyncio.get_event_loop()
        results_zips = loop.run_until_complete(self.download(zips))
        logging.debug(results_zips)
        logging.debug("Getting all git...")
        for git in gits:  # for each git url,
            file_name = self.get_filename(git)  # get the file name
            logging.info(f"getting {file_name}...")
            self.git_clone(git)  # and clone it
            logging.info(f"{file_name} done.")

        logging.info("Installing dependencies...")
        self.apt_update()
        self.install_dependencies("pkgs", results_pkgs)  # install the dependencies pkg
        self.install_dependencies("apts", results_apts)  # install the dependencies pkg
        logging.info("Unzipping dependencies...")
        self.install_dependencies("zips", results_zips)  # unzips the zips
        logging.info("All done!")

    def apt_update(self):
        logging.debug("Updating repositories...")
        with open(devnull, "w") as null:
            subprocess.check_call(
                [
                    "sudo",
                    "apt-get",
                    "update",
                    "-y"
                ],
                stderr=sys.stderr,
                stdout=(
                    sys.stdout
                    if logging.getLogger().isEnabledFor(
                        logging.DEBUG
                    )  # if the user asked for debug mode, let him see the output.
                    else null  # else /dev/null
                ),
            )

    def install_dependencies(self, type, results):

        for file in results:
            if type == "pkgs" or type == "apts":
                logging.debug(f"Installing dependencies{sep}{file}")
                f_path = f"./dependencies{sep}{file}"
                with open(devnull, "w") as null:
                    subprocess.check_call(
                        [
                            "sudo",
                            "apt-get",
                            "install",
                            "-y",
                            f"{f_path if type == 'pkgs' else file}",
                        ],
                        stderr=sys.stderr,
                        stdout=(
                            sys.stdout
                            if logging.getLogger().isEnabledFor(
                                logging.DEBUG
                            )  # if the user asked for debug mode, let him see the output.
                            else null  # else /dev/null
                        ),
                    )
            elif type == "zips":
                logging.debug(f"Unzipping dependencies{sep}{file}")
                with ZipFile(
                        f"dependencies{sep}{file}", "r"
                ) as zip:  # while opening the zip
                    zip.extractall(
                        f"dependencies{sep}{file.rsplit('.', 1)[0]}"
                    )  # extract it and remove the extension (myzip.zip) in the folder myzip
            else:  # if the type is not found, stop everything, we have an issue.
                logging.error("no type found.")
                raise AssertionError(
                    "The type given doesn't match one of the existing one."
                )
            if path.exists(
                    f"dependencies{sep}{file}"
            ):  # delete the files .deb and .zip after all.
                logging.debug(f"Removing file dependencies{sep}{file}")
                remove(f"dependencies{sep}{file}")

    def git_clone(self, url, path=None):
        file_name = self.get_filename(url)
        with open(devnull, "w") as null:
            subprocess.call(
                [
                    "git",
                    "clone",
                    str(url),
                    f"{path if path else 'dependencies' + sep + file_name}",
                ],
                stderr=sys.stderr
                if logging.getLogger().isEnabledFor(logging.DEBUG)
                else null,
                stdout=(
                    sys.stdout
                    if logging.getLogger().isEnabledFor(logging.DEBUG)
                    else null
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

    async def download(self, urls):  # download asynchonously for faster downloads
        async with aiohttp.ClientSession() as session:
            tasks = [self.get_url(url, session) for url in urls]  # load tasks

            return await asyncio.gather(*tasks)  # and gather them

    def get_filename(self, url):  # used to split and get the file name from http url
        fragment_removed = url.split("#")[0]
        query_string_removed = fragment_removed.split("?")[0]
        scheme_removed = query_string_removed.split("://")[-1].split(":")[-1]

        if scheme_removed.find("/") == -1:
            return ""
        return path.basename(scheme_removed)


def main():  # exec main
    if not path.exists("dependencies"):  # if can't find dependency folder
        logging.debug("Folder dependencies does not exist. Creating a new one.")
    else:
        logging.debug("Folder dependencies exist. Removing and creating a new one.")
        rm_rf("dependencies")  # delete the folder
    mkdir("dependencies")  # create the folder
    if path.exists("dependencies.json"):  # if  find the dependency file
        with open("dependencies.json", "r") as dep:  # load dependencies
            data = dep.read()
            dependencies = json.loads(data)
            Install(dependencies)  # install dependencies
    else:  # there's no file dependencies.json
        logging.error("File not found, dependency links are missing. Abort.")
        raise FileNotFoundError("File dependencies is not found, Abort.")


if __name__ == "__main__":
    if geteuid() == 0:  # check if sudo
        main()  # start
    else:
        logging.warning("This tools need SUDO to work!")
        subprocess.check_call(
            ["sudo", sys.executable] + sys.argv
        )  # force sudo, rerun the script as sudo
