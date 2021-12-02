# TLSAssistant v2

**TLSAssistant v2** is the (soon-to-be-released) latest version of TLSAssistant. A complete Python redesign performed to convert the standalone analyzer in a modular framework, extensible with new features and thus capable of streamlining the mitigation process of known and newly discovered TLS attacks even for non-expert users.

⚠`Disclaimer`⚠ TLSAssistant v2 is currently under development, it can be used to preview the newest features but, for everyday use, we suggest to download the latest [stable](https://github.com/stfbk/tlsassistant/releases) release.

![report](assets/report.png)

## Download
You can either download the (new) *in-development* version or the (old) *stable* version of the tool.

### New version (v2.3.1 beta)

#### One Liner (TL;DR)
To install the tool (in a virtual environment), execute the following command:
```bash
  sudo apt update && sudo apt install git python3-dev python3-pip python3-venv -y && git clone https://github.com/stfbk/tlsassistant.git && cd tlsassistant && python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt && python3 install.py -v
```
---

#### Docker

Recommended for non-ubuntu users:

Since it does use APT and install dependencies, we can use the Dockerfile to build the image and contain the installation process.

<details>
<summary>Docker build and run tutorial</summary>

clone the repository:

```bash
  git clone https://github.com/stfbk/tlsassistant.git && cd tlsassistant
```
Build the docker image:
```bash
  docker build -t tlsassistant .
```
Run the docker image:

```bash
docker run --rm -v ${PWD}/results:/tlsassistant/results -t tlsassistant -s fbk.eu
```
add all the `args` that we want to pass after the `tlsassistant` keyword.


We can use the `-v` flag to mount directories with the TLS configuration files.

```bash
docker run --rm -v ${PWD}/results:/tlsassistant/results -v ${PWD}/configurations_to_mount:/tlsassistant/config_mounted -t tlsassistant -f config_mounted/apache.conf
```
</details>

---
#### Step by Step
If you want to execute step by step instead of a one liner:
<details>

<summary>Show single steps</summary>

0. Install git
```bash
sudo apt update && sudo apt-get install git -y
```
1. Download the tool by running

```bash
git clone https://github.com/stfbk/tlsassistant.git && cd tlsassistant
```
2. Install python
  ```bash
  sudo apt update && sudo apt-get install python3-dev python3-pip python3-venv -y
  ```
3. Optional but recommended: Create a virtual environment
  ```bash
  python3 -m venv venv
  ```
  and activate the virtual environment
  ```bash
  source venv/bin/activate
  ```
4. Install the requirements
  ```bash
  pip3 install -r requirements.txt
  ```
5. Run the installer
  ```bash
  python3 install.py
  ```
⚠ Note that the installation of `wkhtmltopdf` is slow. 
To see precisely what the installer is doing, run the command with `-v`.
</details>

#### Usage
```bash
python3 run.py -h
```
<details>

<summary>Show raw output</summary>

```
usage: TLSAssistant [-h] [--version] [-v] [--openssl OPENSSL | --ignore-openssl] [-ot {pdf,html}] [-o OUTPUT] [--group-by {host,module}] (-s SERVER | -f FILE | -d DOMAIN_FILE | -l [LIST] | -a APK)
                    [--apply-fix [APPLY_FIX]] [-c CONFIGURATION | -m CONFIGURATION [CONFIGURATION ...]] [-e EXCLUDE [EXCLUDE ...]]

TLSAssistant Help

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbosity       increase output verbosity
  --openssl OPENSSL, --openssl-version OPENSSL
                        Add openSSL version to consider if configuration analysis is asked.
  --ignore-openssl      During configuration analysis, ignore openssl version completely.
  -ot {pdf,html}, --output-type {pdf,html}
                        The type of the report output.
                        Output type can be omitted and can be obtained by --output extension.
  -o OUTPUT, --output OUTPUT
                        Set report path.
  --group-by {host,module}
                        Choose how to group results by.
  -s SERVER, --server SERVER
                        The hostname, target of the analysis.
  -f FILE, --file FILE  The configuration to analyze.
  -d DOMAIN_FILE, --domain_file DOMAIN_FILE
                        The file path which has the hostname to analyze.
  -l [LIST], --list [LIST]
                        List all modules or print an help of a module.
                        For Example
                        -l freak
  -a APK, --apk APK     The apk path, target of the analysis.
  --apply-fix [APPLY_FIX]
                        Apply fix in the current configuration.
                         Give a path if using -s.
                        i.e.
                                python3 run.py -s fbk.eu --apply-fix myconf.conf
  -c CONFIGURATION, --conf CONFIGURATION, --configuration CONFIGURATION
                        Configuration path.
  -m CONFIGURATION [CONFIGURATION ...], --modules CONFIGURATION [CONFIGURATION ...]
                        List of modules to run
                        For example
                                -m breach crime freak
  -e EXCLUDE [EXCLUDE ...], --exclude EXCLUDE [EXCLUDE ...]
                        List of modules to exclude
                        For example
                                -e breach crime

https://st.fbk.eu -  Security and Trust, FBK Research Unit

```
</details>

##### Examples 
<details>
<summary>Show advanced examples</summary>

- Perform a **server** analysis

```bash
python3 run.py -s fbk.eu
```
<sub>If no configuration or module list provided, `default_server.json` is loaded.</sub>

- Perform a **configuration file** analysis

Here we specify the openssl version of the system which runs the web server.
```bash
python3 run.py -f my_apache_conf.conf --openssl 1.1.1
```

We can also **ignore the openssl version**, assuming the weakest version:
```bash
python3 run.py -f my_apache_conf.conf --ignore-openssl
```

- Perform a **TLS configuration file** analysis and **apply fixes**

By default, the configuration analyzed is changed in place.
```bash
python3 run.py -f my_apache_conf.conf --apply-fix
```

We can specify an **output** path of the fixed configuration:

```bash
python3 run.py -f my_apache_conf.conf --apply-fix my_output_conf.conf
```
- Perform an analysis by **selecting modules**

```bash
python3 run.py -s fbk.eu -m breach crime freak poodle hsts_preloading
```

Or by selecting a **TLSAssistant configuration file**:

```bash
python3 run.py -s fbk.eu -c default_server.json 
```

We can also **exclude some modules** without editing the configuration file:

```bash
python3 run.py -s fbk.eu -c default_server.json -e hsts_preloading
```

get the **full module list** with:
```bash
python3 run.py -l
```

- Perform an analysis with **subdomain enumeration**

```bash
python3 run.py -s *.fbk.eu
```

- Perform an analysis on an **apk file**

```bash
python3 run.py -a my_apk.apk
```

<sub>If no configuration or module list provided, `default_android.json` is loaded.</sub>

- Analyze **all domains in a file** (one per line, including subdomains enumeration)

Assuming the file `domains_list.log` looks like this:
```
music.amazon.it
facebook.com
*.fbk.eu
```
we execute:

```bash
python3 run.py -d domains_list.log
```

</details>


##### Avaliable analysis modules

<details>
<summary>Show modules list</summary>

```bash
python3 run.py -l
```

Results:

```
Here's a list of all the modules available:
Android:
        accepting_all_certificates
        certificate_keystore_disclosure
        hostnameverifier
        obfuscated_code
        ssl_error
        ssl_getinsecure_method
        trustmanager
        weak_algorithms
        webview_ssl_errors
Server:
        3shake
        beast
        breach
        ccs_injection
        certificate_transparency
        crime
        drown
        freak
        heartbleed
        hsts_preloading
        hsts_set
        https_enforced
        logjam
        lucky13
        mitzvah
        nomore
        pfs
        poodle
        renegotiation
        robot
        sloth
        sweet32
        ticketbleed
Use 
        -l module_name
 to read the details.
```

</details>

---

### Old version (v1.\*)
You can download the latest stable release by
- clicking [here](https://github.com/stfbk/tlsassistant/releases);
- cloning from the stable branch by running
    ```bash
    git clone -b v1.x https://github.com/stfbk/tlsassistant.git
    ```
    and then running the `INSTALL.sh` script to install all the dependencies.

## Roadmap

- [x] Design of a **standard** for 
  - [x] module *creation* (to allow the creation of additional modules)
  - [x] module *configuration* (to create new analysis flows using existing modules)
- [x] Refine modules' output
- [x] Design a new report template
- [ ] Documentation writing (ongoing)
- [ ] Creation of new *Output* modules
  - [ ] Configuration analysis
  - [ ] Attack Tree `matching TLSAssistant v1.x output`
  - [ ] STIX `matching TLSAssistant v1.x output`
  - [ ] Scoreboard
- [ ] Improve webserver coverage

## Analysis types
The various types of analysis that can (currently) be requested are:

### Single Host
Since most of the vulnerabilities analyzed by the tool are covered by testssl.sh tool, we decided to make the analysis more efficient by performing a pre-analysis to populate a cache with its result. These will be used by the corresponding testssl.sh modules such as POODLE (an attack that exploits the availability of SSLv3 to downgrade the strength of the connection), during current and future analysis. Thus, in Step 3a the arguments of each individual module related to testssl.sh are obtained. These arguments will be provided to the method in order to perform the testssl.sh pre-analysis and populate the cache with the results. Once this is done, the individual modules are executed (Step 3b) and mitigations added if vulnerable.

### Single APK
Each Android-related module, such as Unsecure TrustManager (which evaluates if a custom implementation may be exploited to break certificate validation), runs the analysis (Step 3b) on the provided APK.

### Multiple Hosts
We perform a Single Host analysis on each one of the domains specified in an input list. Each result is concatenated and provided to the Output module as a single output.	

### TLS Configuration and Fixes
If a configuration file is provided, a WhiteBox analysis is performed by loading the TLS configuration into memory and performing a complete check of all available modules (Step 3b). Otherwise, if a configuration file is provided along with a valid hostname, a singlehost analysis is performed and then the fixes are integrated in the provided TLS configuration. We refer to this analysis as Hybrid: we perform a BlackBox analysis on the hostname and then we apply the fixes on the configuration file.


## License

```
Copyright 2019, Fondazione Bruno Kessler

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Developed within [Security & Trust](https://st.fbk.eu/) Research Unit at [Fondazione Bruno Kessler](https://www.fbk.eu/en/) (Italy)

