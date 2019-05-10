# TLSAssistant

**TLSAssistant** is a fully-featured tool that combines state-of-the-art TLS analyzers with a report system that suggests appropriate mitigations and shows the full set of viable attacks. The companion page can be found [here](https://bit.ly/tlsassistant).

## Features

Thanks to the integrated analyzers, TLSAssistant is currently able to detect and provide mitigations for:

- 3SHAKE
- Bar Mitzvah
- BREACH
- Client-Initiated Renegotiation DoS
- CRIME
- DROWN
- HSTS not set
- HTTPS not enforced
- HTTPS not preloaded
- Lucky13
- Missing Certificate Transparency
- POODLE
- RC4NOMORE
- ROBOT
- SLOTH
- Sweet32
- Unsecure Android TrustManagers

## Dependencies

To be able to run TLSAssistant you will need a set of dependencies that can be automatically downloaded by running `INSTALL.sh`.

It will download (and place in the correct folders) the following:

- packages: `aha`, `html2text`, `libxml2-utils`, `git`, `curl`, `python2`, `androguard`.
- tools: `mallodroid`, `testssl.sh`, `tlsfuzzer`, `TLS Extended_Master_Checker`.

## Download

You can install TLSAssistant by cloning this git repository:

```bash
git clone https://github.com/stfbk/tlsassistant.git
```

and running the `INSTALL.sh` script to install all the dependencies.


## Usage

Once in the right directory, run 
```bash
bash TLSAssistant.sh <parameters>
```

where

### Parameters

- `-h|--help` show the help
- `-s|--server [URL|IP] {port}` analyze a server, default port: *433*
- `-a|--apk <file>` check an apk installer
- `-v [0|1|2]` verbosity level

### Verbosity level

- 0: mitigations' description
- 1: previous + code snippets [default]
- 2: previous + tools' individual reports

example: `bash TLSAssistant.sh -s github.com`

## Credits

TLSAssistant exists thanks to the following open-source projects (from a to z):

- [Androguard](https://github.com/androguard/androguard)
- [mallodroid](https://github.com/sfahl/mallodroid)
- [markdown.bash](https://github.com/chadbraunduin/markdown.bash)
- [testssl.sh](https://github.com/drwetter/testssl.sh)
- [tlsfuzzer](https://github.com/tomato42/tlsfuzzer)
- [TLS Extended_Master_Checker](https://github.com/Tripwire-VERT/TLS_Extended_Master_Checker)



Developed within [Security & Trust](https://st.fbk.eu) Research Unit at [Fondazione Bruno Kessler](https://www.fbk.eu/en/) (Italy)