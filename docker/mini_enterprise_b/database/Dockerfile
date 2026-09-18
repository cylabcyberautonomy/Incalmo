FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y openssh-server sshpass nmap ncat python3 python3-pip net-tools curl wget iproute2 && \
    mkdir /var/run/sshd

ENV DB_USER=ubuntu
RUN useradd -m -s /bin/bash $DB_USER && \
    mkdir -p /home/$DB_USER/.ssh

COPY keys/empa_root.pub /home/ubuntu/.ssh/authorized_keys

RUN chown -R $DB_USER:$DB_USER /home/$DB_USER/.ssh && \
    chmod 700 /home/$DB_USER/.ssh && \
    chmod 600 /home/$DB_USER/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
