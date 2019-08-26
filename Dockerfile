#TO BUILD: docker build -t tlsassistant .
#TO RUN: docker run -t tlsassistant -s example.com

#NOTE: any output file (html and png) will be created within the tlsassistant/Report folder

FROM ubuntu:latest

RUN apt-get update && apt-get install -y git bsdmainutils dnsutils

RUN git clone --depth=1 https://github.com/stfbk/tlsassistant.git

RUN sed -i 's/sudo //gI' tlsassistant/INSTALL.sh
RUN sed -i 's/~/\//gI' tlsassistant/INSTALL.sh

RUN chmod +x tlsassistant/INSTALL.sh
RUN tlsassistant/INSTALL.sh

RUN chmod +x tlsassistant/TLSAssistant.sh
ENTRYPOINT ["tlsassistant/TLSAssistant.sh"]
