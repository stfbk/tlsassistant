#TO BUILD: docker build -t tlsassistant .
#TO RUN: docker run -t tlsassistant -s example.com

#NOTE: any output file (html and png) will be created within the tlsassistant/Report folder

FROM ubuntu:latest

RUN apt-get update && apt-get install -y git python3-dev python3-pip sudo

RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata keyboard-configuration

RUN git clone https://github.com/stfbk/tlsassistant.git

WORKDIR "/tlsassistant"

RUN pip3 install -r requirements.txt

ENV TLSA_IN_A_DOCKER_CONTAINER Yes

RUN python3 install.py -v


ENTRYPOINT ["python3", "run.py"]