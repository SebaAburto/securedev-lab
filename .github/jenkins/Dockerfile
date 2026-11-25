FROM jenkins/jenkins:lts-jdk17
USER root
# Docker CLI + Compose (el daemon es el de Docker Desktop, vía /var/run/docker.sock) y Python para las pruebas
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 python3-venv python3-pip \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list \
 && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
 && rm -rf /var/lib/apt/lists/*
USER jenkins
RUN jenkins-plugin-cli --plugins git workflow-aggregator pipeline-stage-view junit timestamper ws-cleanup credentials-binding
