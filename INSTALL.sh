#!/bin/bash
set -e #stop the script if any error occours

err_report() {
    echo "Error on line $1"
}

## echo functions definition (https://stackoverflow.com/a/42449998/3370955)
function r_echo {
    echo -e '\033[7m'$1'\033[0m'
}
function b_echo {
    echo -e '\033[1m'$1'\033[0m'
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR #moving to the right path

b_echo "################"
b_echo "# TLSAssistant #"
b_echo "################"
echo ""
r_echo "# Installing dependencies..."
sudo apt-get update
sudo apt-get install -y aha html2text libxml2-utils git unzip curl wget graphviz python3-dev python3-venv
#try to install aria2 for faster downloads
sudo apt-get install -y aria2

if ! [[ $(command -v super-analyzer) ]]; then
    if [[ $(command -v aria2c) ]]; then

    aria2c -q https://github.com/SUPERAndroidAnalyzer/super/releases/download/0.5.1/super-analyzer_0.5.1_ubuntu_amd64.deb -o super-analyzer.deb
    else
    wget  -O super-analyzer.deb https://github.com/SUPERAndroidAnalyzer/super/releases/download/0.5.1/super-analyzer_0.5.1_ubuntu_amd64.deb

    fi

    sudo apt-get install -y ./super-analyzer.deb
    rm ./super-analyzer.deb
fi


echo ""
r_echo "Utilities installed"
    echo ""
if ! [[ $(command -v pip) ]]; then
    sudo apt-get install -y python3-pip
    r_echo "pip installed"
else
    r_echo "pip already installed"
fi
#pip3 install virtualenv

#virtualenv -p python2 python_dep
r_echo "Creating VENV..."
python3 -m venv python_dep
python_dep/bin/pip install wheel
python_dep/bin/pip install androguard
r_echo "Androguard installed"
python_dep/bin/pip install --pre tlslite-ng
r_echo "TLS Lite installed"
python_dep/bin/pip install stix2
r_echo "stix2 installed"
echo ""

mkdir -p utility
curl -s https://raw.githubusercontent.com/chadbraunduin/markdown.bash/master/markdown.sh > utility/markdown.sh
r_echo "markdown.sh installed"
echo ""
git clone https://github.com/UnaPibaGeek/ctfr.git ./utility/ctfr > /dev/null 2>&1
python_dep/bin/pip install -r ./utility/ctfr/requirements.txt
r_echo "ctfr installed"
echo ""

r_echo "# Installing tools..."
echo ""
r_echo "## Downloading mallodroid..."
git clone https://github.com/stfbk/mallodroid.git ./Analyzer/tools/others/mallodroid > /dev/null 2>&1 
b_echo "Done"

echo ""
r_echo "## Downloading tlsfuzzer..."
git clone https://github.com/tomato42/tlsfuzzer.git ./Analyzer/tools/server/tlsfuzzer > /dev/null 2>&1
mkdir -p Analyzer/tools/server/utils
openssl req -x509 -newkey rsa -keyout Analyzer/tools/server/utils/localuser.key \-out Analyzer/tools/server/utils/localuser.crt -nodes -batch -subj /CN=Local\ User 2>/dev/null #generating the required certificate
b_echo "Done"

echo ""
r_echo "## Downloading testssl.sh..."
if [[ $(command -v aria2c) ]]; then
    aria2c -q https://github.com/drwetter/testssl.sh/archive/3.0.4.zip -o 3.0.4.zip
else
    wget --no-check-certificate -N -nd https://github.com/drwetter/testssl.sh/archive/3.0.4.zip > /dev/null 2>&1
fi
unzip -o 3.0.4.zip -d ./Analyzer/tools/server > /dev/null 2>&1
rm 3.0.4.zip
b_echo "Done"

echo ""
b_echo "Installation completed successfully!"
echo ""
