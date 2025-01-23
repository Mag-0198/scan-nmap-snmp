FROM ubuntu:22.04

# Instalar nmap y snmp
RUN apt update && \
    apt install -y software-properties-common &&\
    apt install -y nmap snmp &&\
    apt install -y iproute2 &&\
    apt install -y curl && \
    apt install -y isc-dhcp-client && \
    apt install -y net-tools && \
    apt install -y openssh-client && \
    apt install -y telnet && \
    apt install -y traceroute && \
    apt install -y iputils-ping && \
    apt install -y nano &&\
    apt install -y sudo &&\
    apt install -y pip &&\
    apt install -y cron && \
    apt clean &&\
    rm -rf /var/lib/apt/lists/*

# Copiar los archivos del proyecto al contenedor
COPY . /app

# Establecer el directorio de trabajo en el contenedor
WORKDIR /app

# Instalar las dependencias de Python
#RUN pip install -r requirements.txt


# Comando para ejecutar el script principal
#CMD ["tail", "-f", "/dev/null"]
CMD ["python3", "scan.py"]

