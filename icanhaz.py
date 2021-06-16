#!/usr/bin/env python
"""Unified icanhaz services handler."""
import shlex
import socket
import subprocess

import dns.resolver
import dns.reversename
from flask import Flask, request, Response

app = Flask(__name__)
TRACEROUTE_BIN = "/usr/bin/traceroute"


def find_remote_addr():
    """Determine the correct IP address of the requester."""
    if request.headers.get('CF-Connecting-IP'):
        return request.headers.get('CF-Connecting-IP')
    return request.remote_addr


def get_ptr():
    """Get a reverse DNS record."""
    remote_addr = find_remote_addr()
    try:
        reversed_address = dns.reversename.from_address(remote_addr)
        response = dns.resolver.resolve(reversed_address, "PTR")[0]
        return str(response).rstrip('.')
    except Exception:
        return remote_addr


def get_traceroute(lookup=False):
    """Run a traceroute and return the results."""
    remote_addr = find_remote_addr()
    return run_traceroute(remote_addr, lookup)


def run_traceroute(remote_addr, lookup=False):
    """Run traceroute and return the results."""
    extra_args = ""
    if not lookup:
        extra_args += "-n "

    tracecmd = shlex.split(
        f"{TRACEROUTE_BIN} -q 1 -f 1 -w 1 {extra_args} {remote_addr}"
    )
    result = subprocess.Popen(
        tracecmd,
        stdout=subprocess.PIPE
        ).communicate()[0].strip()
    return result.decode('utf-8')


def validate_ip(remote_addr):
    """Verify the IP address is valid before running traceroute."""
    valid_ip = False
    remote_addr = find_remote_addr()
    try:
        socket.inet_pton(socket.AF_INET, remote_addr)
        valid_ip = True
    except socket.error:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, remote_addr)
        valid_ip = True
    except socket.error:
        pass

    return valid_ip


@app.route("/")
def handler():
    """Run traceroute and return the output."""

    if not validate_ip(request.remote_addr):
        return Response(
            "🛑 Invalid IP\n",
            mimetype="text/plain",
            status=406
        )

    if request.host.endswith("icanhaztraceroute.com"):
        result = get_traceroute(lookup=True)
    elif request.host.endswith("icanhaztrace.com"):
        result = get_traceroute(lookup=False)
    else:
        result = get_ptr()

    return Response(
        f"{result}\n",
        mimetype="text/plain"
    )


if __name__ == "__main__":
    app.debug = 1
    app.run(host='0.0.0.0')
