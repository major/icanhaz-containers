FROM registry.fedoraproject.org/fedora:37
RUN echo "fastestmirror=1" >> /etc/dnf/dnf.conf
RUN dnf -y install python3 python3-dns python3-flask python3-gunicorn python3-pip traceroute
RUN dnf clean all
COPY icanhaz.py /
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "icanhaz:app"]
