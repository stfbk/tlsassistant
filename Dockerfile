#TO BUILD: docker build -t tlsassistant .
#TO RUN: docker run -t tlsassistant -s example.com

#NOTE: any output file (html and png) will be created within the tlsassistant/Report folder

FROM ubuntu:22.04

ENV PATH="/root/.local/bin:$PATH"

ENV DEBIAN_FRONTEND=noninteractive

ENV LANG=en_US.UTF-8

ENV LANGUAGE=en_US:en

ENV LC_ALL=en_US.UTF-8

ENV TZ=Europe/Rome

RUN apt-get update && apt-get install -y git python3-dev python3-pip sudo bsdmainutils locales dnsutils tzdata keyboard-configuration pipx

RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen

RUN pipx install poetry

RUN pipx ensurepath
    
COPY . /tlsassistant

WORKDIR "/tlsassistant"

RUN poetry install

ENV TLSA_IN_A_DOCKER_CONTAINER=Yes

RUN poetry run python3 install.py -v


ENTRYPOINT ["poetry", "run", "python3", "run.py"]
