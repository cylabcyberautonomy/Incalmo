FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install -y openssh-server sshpass nmap python3 python3-pip net-tools curl wget iproute2 && \
    apt-get install -y --allow-downgrades sudo=1.8.21p2-3ubuntu1 && \
    apt-mark hold sudo && \
    mkdir /var/run/sshd

ENV EMPLOYEE_USER=ubuntu
RUN useradd -m -s /bin/bash $EMPLOYEE_USER && \
    mkdir -p /home/$EMPLOYEE_USER/.ssh /root/.ssh

ARG AUTHORIZED_KEYS=keys/empty
ARG ROOT_KEY=keys/empty
ARG ROOT_PUB=keys/empty
ARG ROOT_CONFIG=keys/empty

COPY ${AUTHORIZED_KEYS} /home/ubuntu/.ssh/authorized_keys
COPY ${ROOT_KEY} /root/.ssh/id_rsa
COPY ${ROOT_PUB} /root/.ssh/id_rsa.pub
COPY ${ROOT_CONFIG} /root/.ssh/config

RUN chown -R $EMPLOYEE_USER:$EMPLOYEE_USER /home/$EMPLOYEE_USER/.ssh && \
    chmod 700 /home/$EMPLOYEE_USER/.ssh && \
    chmod 600 /home/$EMPLOYEE_USER/.ssh/authorized_keys && \
    chmod 700 /root/.ssh && \
    chmod 600 /root/.ssh/id_rsa /root/.ssh/config && \
    chmod 644 /root/.ssh/id_rsa.pub

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
