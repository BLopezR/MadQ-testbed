FROM ubuntu:22.04

# Actualiza el sistema e instala sudo
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nano sudo openssh-server iproute2 iputils-ping tcpdump traceroute psmisc
RUN groupadd -g 1000 ubuntu
RUN useradd -d /home/ubuntu -s /bin/bash -m ubuntu -u 1000 -g 1000 && echo "ubuntu:ubuntu" | chpasswd && adduser ubuntu sudo

# Permite que el usuario "ubuntu" ejecute comandos con sudo sin contraseña
RUN echo "ubuntu ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu && \
    chmod 0440 /etc/sudoers.d/ubuntu

# Establece al usuario "ubuntu" como el usuario por defecto
USER ubuntu

# Establece el directorio de trabajo en el directorio home del usuario "ubuntu"
WORKDIR /home/ubuntu

COPY . ./

# Instala paquetes necesarios para Python
RUN sudo apt-get update && \
    sudo apt-get install -y python3 python3-pip

# Añade .local/bin/ al PATH
ENV PATH="/home/ubuntu/.local/bin:${PATH}"

RUN pip3 install --user "flask"

WORKDIR /home/ubuntu

CMD ["tail", "-f", "/dev/null"]