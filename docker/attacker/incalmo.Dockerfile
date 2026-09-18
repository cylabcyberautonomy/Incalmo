FROM kalilinux/kali-last-release

RUN apt-get update && apt-get install -y python3 python3-pip
RUN apt-get install -y nmap net-tools golang-go curl wget sshpass procps nikto

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
ENV GOPATH /root/go
ENV PATH $GOPATH/bin:$PATH

# Install Metasploit dependencies
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall

RUN pip install --break-system-packages uv

# Create ssh directory and server directory
RUN mkdir -p /root/.ssh
RUN mkdir -p /server

# Create ssh key
RUN ssh-keygen -b 2048 -t rsa -f '/root/.ssh/id_rsa' -q -N ""

# Set key permissions
RUN chmod 600 /root/.ssh/id_rsa
RUN chmod 700 /root/.ssh

# Copy attacker files
COPY ./ /incalmo
COPY ./incalmo/c2server/agents /agents
WORKDIR /incalmo

# Install dependencies
RUN uv sync

RUN apt-get install -y iproute2

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/incalmo

# Run the startup script
CMD ["bash", "./docker/attacker/start.sh"]