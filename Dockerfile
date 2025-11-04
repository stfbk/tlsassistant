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

RUN apt-get update && apt-get install -y git python3-dev python3-pip sudo bsdmainutils locales dnsutils tzdata keyboard-configuration pipx \
    libcairo2-dev openjdk-11-jre openjdk-11-jdk

RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen

RUN pipx install poetry

RUN pipx ensurepath

WORKDIR "/tlsassistant"
COPY ./dependencies.json /tlsassistant/dependencies.json
COPY ./pyproject.toml /tlsassistant/pyproject.toml
RUN poetry install

COPY ./install.py /tlsassistant/install.py
COPY ./utils/logger.py /tlsassistant/utils/logger.py
COPY ./utils/colors.py /tlsassistant/utils/colors.py
COPY ./ciphersuites_converter.py /tlsassistant/ciphersuites_converter.py
COPY ./configs/compliance/ciphersuites.json /tlsassistant/configs/compliance/ciphersuites.json

ENV TLSA_IN_A_DOCKER_CONTAINER=Yes

RUN poetry run python3 install.py -v

WORKDIR "/tlsassistant/dependencies/tls-compliance-dataset"

RUN poetry run python3 -m pip install -r requirements.txt

RUN poetry run python3 schema_creator.py

RUN poetry run python3 database_filler.py

RUN cp requirements.db /tlsassistant/dependencies/

COPY . /tlsassistant

WORKDIR "/tlsassistant"

ENTRYPOINT ["poetry", "run", "python3", "run.py"]
