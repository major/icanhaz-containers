import json
import shlex
import socket
import subprocess

from flask import Flask, request, Response

app = Flask(__name__)
traceroute_bin = "/usr/bin/traceroute"

def find_remote_addr(req):
    """Determine the correct IP address of the requester."""
    if req.headers.get('CF-Connecting-IP'):
        return req.headers.get('CF-Connecting-IP')
    return req.remote_addr

def validate_ip(remote_addr):
    """Verify the IP address is valid before running traceroute."""
    valid_ip = False
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

def run_traceroute(remote_addr):
    """Run traceroute and return the results."""
    tracecmd = shlex.split(
        f"{traceroute_bin} -q 1 -w 1 {remote_addr}"
    )
    result = subprocess.Popen(
        tracecmd,
        stdout=subprocess.PIPE
        ).communicate()[0].strip()
    return result.decode('utf-8')

@app.route("/")
def handler():
    """Run traceroute and return the output."""
    remote_addr = find_remote_addr(request)
    valid_ip = validate_ip(remote_addr)

    if not valid_ip:
        return Response("Invalid IP", status=406)

    traceroute_output = run_traceroute(remote_addr)

    return Response(
        f"{traceroute_output}\n",
        mimetype="text/plain"
    )