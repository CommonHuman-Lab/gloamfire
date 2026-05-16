FROM ubuntu:24.04

ARG WAZUH_VERSION=4.8.2-1

# Install deps; allow unauthenticated repos to handle Ubuntu GPG key rotation.
RUN apt-get -o Acquire::AllowInsecureRepositories=true \
            -o APT::Get::AllowUnauthenticated=true update \
    && apt-get -o APT::Get::AllowUnauthenticated=true install -y \
        --no-install-recommends ca-certificates curl lsb-release debconf adduser \
    && rm -rf /var/lib/apt/lists/*

# Download wazuh-agent directly from Wazuh's package server (no apt repo / GPG needed).
RUN curl -fsSL -o /tmp/wazuh-agent.deb \
    "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}_amd64.deb" \
    && dpkg -i /tmp/wazuh-agent.deb \
    && rm /tmp/wazuh-agent.deb

RUN mkdir -p /var/log/gloamfire

COPY ossec.conf /var/ossec/etc/ossec.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
