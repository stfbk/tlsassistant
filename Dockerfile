#TO BUILD: docker build -t tlsassistant .
#TO RUN: docker run -t tlsassistant -s example.com

#NOTE: any output file (html and png) will be created within the tlsassistant/Report folder

FROM ubuntu:latest

ENV LC_ALL=en_US.UTF-8

RUN apt-get update && apt-get install -y git python3-dev python3-pip sudo bsdmainutils locales dnsutils

RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen

ENV LANG en_US.UTF-8  

ENV LANGUAGE en_US:en  

ENV LC_ALL en_US.UTF-8    

RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata keyboard-configuration

COPY . /tlsassistant

WORKDIR "/tlsassistant"

RUN pip3 install -r requirements.txt

ENV TLSA_IN_A_DOCKER_CONTAINER Yes

RUN python3 install.py -v


ENTRYPOINT ["python3", "run.py"]
