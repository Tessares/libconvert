FROM ubuntu:19.04

LABEL maintainer="Tessares (contact gregory.vanderschueren@tessares.net)"
LABEL description="All deps for building & running tests of libconvert"

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
