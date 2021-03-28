FROM docker.io/library/archlinux:latest
RUN pacman -Sy --noconfirm python python-pip traceroute && pacman -Scc --noconfirm
RUN pip install gunicorn flask
COPY icanhaz.py /
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "icanhaz:app"]