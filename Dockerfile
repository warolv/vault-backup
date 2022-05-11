# syntax=docker/dockerfile:1.2.1

FROM python:3

LABEL name="vault-backup" version="0.0.1"

# Explicitly set user/group IDs
RUN groupadd -r jenkins --gid=1000 && useradd -m -r -g jenkins --uid=1000 jenkins

USER jenkins

COPY requirements.txt /
RUN pip install -r requirements.txt

COPY vault_handler.py /

CMD [ "python", "./vault_handler.py" ]

HEALTHCHECK NONE

# dockerfile_lint - ignore
EXPOSE 80
