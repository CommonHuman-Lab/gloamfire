# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""PCAP capture helper — wraps tcpdump inside a victim container."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path

from gloamfire.core.docker_client import DockerClient

log = logging.getLogger(__name__)

_PCAP_TMP = "/tmp/gloamfire_capture.pcap"
_PID_TMP = "/tmp/gloamfire_tcpdump.pid"


class PcapCapture:
    """Start/stop tcpdump inside a container and copy the result to the host."""

    def __init__(
        self,
        docker_client: DockerClient,
        container: str = "gloamfire-ubuntu",
        iface: str = "eth0",
    ) -> None:
        self._docker = docker_client
        self._container = container
        self._iface = iface
        self._active = False

    def start(self) -> bool:
        cmd = (
            f"rm -f {_PCAP_TMP} {_PID_TMP} && "
            f"tcpdump -i {self._iface} -w {_PCAP_TMP} > /dev/null 2>&1 & "
            f"echo $! > {_PID_TMP}"
        )
        try:
            self._docker.exec_in_container(self._container, cmd)
            time.sleep(0.5)  # give tcpdump time to open the interface
            self._active = True
            log.debug("pcap capture started on %s:%s", self._container, self._iface)
            return True
        except Exception as exc:
            log.warning("Could not start pcap capture: %s", exc)
            return False

    def stop(self, output_path: Path) -> bool:
        if not self._active:
            return False
        try:
            self._docker.exec_in_container(
                self._container,
                f"kill -TERM $(cat {_PID_TMP} 2>/dev/null) 2>/dev/null || pkill tcpdump 2>/dev/null || true",
            )
            time.sleep(1)  # let tcpdump flush write buffer
            output_path.parent.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(
                ["docker", "cp", f"{self._container}:{_PCAP_TMP}", str(output_path)],
                capture_output=True,
                check=False,
            )
            self._docker.exec_in_container(
                self._container,
                f"rm -f {_PCAP_TMP} {_PID_TMP}",
            )
            self._active = False
            if r.returncode == 0 and output_path.exists():
                kb = output_path.stat().st_size // 1024
                log.debug("pcap saved: %s (%d KB)", output_path, kb)
                return True
            log.warning("docker cp failed (rc=%d): %s", r.returncode, r.stderr.decode())
        except Exception as exc:
            log.warning("Could not stop pcap capture: %s", exc)
        return False
