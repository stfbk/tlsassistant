# TLSAssistant v2

**TLSAssistant v2** is the (soon-to-be-released) latest version of TLSAssistant, a complete Python redesign performed to convert the standalone analyzer in a modular framework, extensible with new features and thus capable of streamlining the mitigation process of known and newly discovered TLS attacks even for non-expert users.

⚠`Disclaimer`⚠ TLSAssistant v2 is currently under development, it can be used to preview the newest features but, for everyday use, we suggest to download the latest [stable](https://github.com/stfbk/tlsassistant/releases) release.

## Download
You can either download the *in-development* or the *stable* version of the tool.

### Bleeding-edge (v2)

You can download the tool by running

```bash
git clone https://github.com/stfbk/tlsassistant.git
```


### Stable version (v1.\*)
You can download the latest stable release by
- clicking [here](https://github.com/stfbk/tlsassistant/releases);
- cloning from the stable branch by running
    ```bash
    git clone -b 1.x https://github.com/stfbk/tlsassistant.git
    ```
    and then running the `INSTALL.sh` script to install all the dependencies.

## Roadmap

- [ ] Match TLSAssistant v1.x's remaining set of features
  - [ ] Attack Trees output
  - [ ] STIX output
- [ ] Create new *Analysis* Modules
  - [ ] [ALPACA Attack](https://alpaca-attack.com/) 
  - [ ] [Raccoon Attack](https://raccoon-attack.com/)
  - [ ] [Zombie POODLE and GOLDENDOODLE](https://github.com/tls-attacker/TLS-Padding-Oracles)
  - [ ] [Certificate chain validation](https://medium.com/@sleevi_/path-building-vs-path-verifying-the-chain-of-pain-9fbab861d7d6)
- [ ] Improve webserver coverage
- [ ] Create a toy module to streamline the creation of third-party modules

## Architecture

![architecture](assets/architecture.png)

The architecture is composed of three types of modules: *Analysis* modules to perform vulnerability checks, *Core* modules to act as a junction between modules by exchanging information in appropriate formats, and *Output* modules to provide properly formatted output to the user. The tool has two main users: the third-party developer who will create new modules, and the end-user who will use the tool to analyze TLS-related vulnerabilities.


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

