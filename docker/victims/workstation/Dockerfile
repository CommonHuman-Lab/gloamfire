# OctoRig Workstation Victim — simulates an enterprise workstation
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    netcat-openbsd \
    dnsutils \
    bash \
    cron \
    python3 \
    openssh-client \
    git \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Simulate a typical workstation user
RUN useradd -ms /bin/bash analyst && \
    mkdir -p /home/analyst/Documents /home/analyst/Downloads && \
    chown -R analyst:analyst /home/analyst

# Pre-populate with realistic decoy files
RUN for i in $(seq 1 10); do \
      echo "Q$(date +%Y)-Report-$i: confidential revenue data" > \
        /home/analyst/Documents/Q_Report_$i.txt; \
    done

USER analyst
WORKDIR /home/analyst

CMD ["/bin/bash", "-c", "while true; do sleep 30; done"]
