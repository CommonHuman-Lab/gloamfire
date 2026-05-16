# OctoRig Ubuntu Victim — simulation target
# Pre-loaded with tools needed for all built-in attack simulations.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    netcat-openbsd \
    dnsutils \
    nmap \
    python3 \
    python3-pip \
    bash \
    cron \
    procps \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root simulation user for lower-privilege scenarios
RUN useradd -ms /bin/bash octorig

WORKDIR /home/octorig

# Heartbeat loop — keeps container alive and generates periodic telemetry
CMD ["/bin/bash", "-c", "while true; do sleep 30; done"]
