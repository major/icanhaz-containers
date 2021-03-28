import os
import socket

from flask import Flask, request, Response

app = Flask(__name__)

def find_remote_addr(req):
    """Determine the correct IP address of the requester."""
    if req.headers.get('CF-Connecting-IP'):
        return req.headers.get('CF-Connecting-IP')
    if req.headers.get('X-Forwarded-For'):
        return req.headers.get('X-Forwarded-For')
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

@app.route("/")
def handler():
    """Run traceroute and return the output."""
    remote_addr = find_remote_addr(request)
    valid_ip = validate_ip(remote_addr)

    if not valid_ip:
        return Response("Invalid IP", status=406)

    try:
        output = socket.gethostbyaddr(remote_addr)
        result = output[0]
    except:
        result = remote_addr

    return Response(
        f"{result}\n",
        mimetype="text/plain"
    )
