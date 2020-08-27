FROM ubuntu:19.04

LABEL maintainer="Tessares (contact gregory.vanderschueren@tessares.net)"
LABEL description="All deps for building & running tests of libconvert"

# Ubuntu 19.04 is EOL
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Brussels

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    check \
    clang-tools-6.0 \
    cmake \
    cppcheck \
    curl \
    iproute2 \
    iptables \
    libcapstone-dev \
    pandoc \
    pkg-config \
    python3 \
    python3-pip \
    python3-setuptools \
    tcpdump \
    uncrustify \
    wget

RUN pip3 install scapy
