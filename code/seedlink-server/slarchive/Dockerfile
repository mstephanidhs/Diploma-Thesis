# -*- coding: utf-8 -*-

#    Copyright (C) 2021 Triantafyllis Nikolaos

#    This file is part of Gisola.

#    Gisola is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, 
#    or any later version.

#    Gisola is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with Gisola.  If not, see <https://www.gnu.org/licenses/>.

# This Dockerfile appears to set up an environment for running the SeisComP 
# software along with related tools and dependencies within a Docker container. 
# It also includes configurations for SSH, VNC, and XFCE desktop environment

# specifies the base image as Ubuntu 20.04
FROM ubuntu:20.04

# install various packages
RUN apt-get update -y && apt-get install -y sudo wget python3 libpython3.8 lsb-release nano

# creates a group called "sysop" and a user named "sysop" with certain configurations
RUN groupadd sysop
RUN useradd -rm -d /home/sysop -s /bin/bash -g sysop -G sudo -u 1001 sysop -p sysop
RUN passwd -d sysop

# switches the user context to "sysop" and sets the working directory to "/home/sysop"
USER sysop
WORKDIR /home/sysop

# donwloads several necessary SeisComP files
RUN wget 'https://www.seiscomp.de/downloader/seiscomp-4.6.0-ubuntu20.04-x86_64.tar.gz'
RUN wget 'https://www.seiscomp.de/downloader/seiscomp-maps.tar.gz'
RUN wget 'https://www.seiscomp.de/downloader/seiscomp-4.6.0-doc.tar.gz'

# extracts the necessary files
# -x: tells 'tar' to extract files
# -f: specifies the filename of the archive to work with
# &&: operator that means "and then", it is used to execute the next command only if the previous one succeeds

RUN tar -xf seiscomp-4.6.0-ubuntu20.04-x86_64.tar.gz && rm seiscomp-4.6.0-ubuntu20.04-x86_64.tar.gz

RUN tar -xf seiscomp-maps.tar.gz && rm seiscomp-maps.tar.gz

RUN tar -xf seiscomp-4.6.0-doc.tar.gz && rm seiscomp-4.6.0-doc.tar.gz

# noninteractive: will not interactively ask for user input during package installation. It will use default 
# values and assume "yes" for any prompts that may arise during installation (-y)
RUN sudo DEBIAN_FRONTEND="noninteractive" apt-get install tzdata -y

RUN sudo apt update -y

# sh -c: starts a new shell process with the -c option which is used to execute a command provided as an argument
# -e: enables interpretation of escape sequences
# |: is used to take the output of the command on its left and use it as input for the command on its right
RUN sh -c /bin/echo -e "y" | sudo ./seiscomp/bin/seiscomp install-deps base

RUN sh -c /bin/echo -e "y" | sudo ./seiscomp/bin/seiscomp install-deps fdsnws

RUN sh -c /bin/echo -e "y" | sudo ./seiscomp/bin/seiscomp install-deps mariadb-server

RUN mkdir /home/sysop/.seiscomp

# chown command is used to change ownership of the specified directories
# sysop:sysop: This specifies both the user and group to which ownership is being changed
# -R: This is an option that makes chown operate recursively. It means that the ownership of the specified 
# directories and all of their contents will be changed
RUN sudo chown sysop:sysop -R /home/sysop/seiscomp /home/sysop/.seiscomp

# 777: This is the permission setting. In octal notation, 777 grants full read, write, and execute permissions to 
# the owner, group, and others. Essentially, it provides unrestricted access to everyone.
RUN sudo chmod -R 777 /home/sysop/seiscomp /home/sysop/.seiscomp

# sed: used to perform a text replacement
# i: changes will be made directly to the specified file (2nd argument) rather than displaying the output to the terminal
# indicates that you want to replace "localhost" with "gisola-db."
# /g: This is a flag that makes the replacement global, meaning it replaces all occurrences of "localhost"  
# in the file, not just the first one.
RUN sed -i 's/localhost/gisola-db/g' /home/sysop/seiscomp/etc/defaults/scmaster.cfg
#RUN echo 'serveDataSelect = false\nserveStation = false' >> /home/sysop/seiscomp/etc/defaults/fdsnws.cfg

COPY ./wait-for-it.sh /home/sysop
RUN sudo chmod -R 777 ./wait-for-it.sh

RUN sudo apt-get install python3-pyqt5 -y

# >> /home/sysop/.bashrc: This part of the command redirects (appends) the output of the echo command to the .bashrc file in the /home/sysop/ directory. The >> operator is used to append the content to the end of the file rather than overwriting it.
# SEISCOMP_ROOT: Sets the SEISCOMP_ROOT environment variable to "/home/sysop/seiscomp."
# PATH: Adds the "/home/sysop/seiscomp/bin" directory to the beginning of the PATH environment variable, which allows the user to run executables from that directory without specifying the full path.
# LD_LIBRARY_PATH: Adds the "/home/sysop/seiscomp/lib" directory to the LD_LIBRARY_PATH environment variable, which helps the system locate shared libraries.
# PYTHONPATH: Adds the "/home/sysop/seiscomp/lib/python" directory to the PYTHONPATH environment variable, allowing Python to find modules in that directory.
# MANPATH: Adds the "/home/sysop/seiscomp/share/man" directory to the MANPATH environment variable, which helps the system find manual pages.
# LC_ALL: Sets the LC_ALL environment variable to "C," which sets the locale to the "C" locale, often used for predictable character encoding.
# source "/home/sysop/seiscomp/share/shell-completion/seiscomp.bash": Sources the "seiscomp.bash" script from the "/home/sysop/seiscomp/share/shell-completion/" directory, which can provide shell completion for SeisComP-related commands and functionality.
RUN echo "\nexport SEISCOMP_ROOT=\"/home/sysop/seiscomp\"\nexport PATH=\"/home/sysop/seiscomp/bin:$PATH\"\nexport LD_LIBRARY_PATH=\"/home/sysop/seiscomp/lib:$LD_LIBRARY_PATH\"\nexport PYTHONPATH=\"/home/sysop/seiscomp/lib/python:$PYTHONPATH\"\nexport MANPATH=\"/home/sysop/seiscomp/share/man:$MANPATH\"\nexport LC_ALL=C\nsource \"/home/sysop/seiscomp/share/shell-completion/seiscomp.bash\"\n" >> /home/sysop/.bashrc

# openssh-server: server package, which is used for secure remote access to the container.
RUN sudo apt install -y openssh-server xauth

# sudo mkdir /var/run/sshd: This command creates the /var/run/sshd directory. This directory is typically used by the SSH server (sshd) to store its runtime information.
# mkdir /home/sysop/.ssh: This command creates the .ssh directory in the home directory of the user "sysop." The .ssh directory is used to store SSH-related configuration files and keys.
# chmod 700 /home/sysop/.ssh: This command sets the permissions of the .ssh directory to 700, which means that only the owner (in this case, the "sysop" user) has read, write, and execute permissions, while others have no access.
# sudo ssh-keygen -t rsa -N '' -f /home/sysop/.ssh/id_rsa: This command generates an SSH key pair for the "sysop" user with the following components:
# ssh-keygen: This is the command to generate SSH key pairs.
# -t rsa: This specifies the key type as RSA.
# -N '': This sets an empty passphrase for the private key. It means the private key won't be protected by a passphrase, which can be useful for automation.
# -f /home/sysop/.ssh/id_rsa: This specifies the file path where the generated private key (id_rsa) will be saved.
RUN sudo mkdir /var/run/sshd \
    && mkdir /home/sysop/.ssh \
    && chmod 700 /home/sysop/.ssh \
    && sudo ssh-keygen -t rsa -N '' -f /home/sysop/.ssh/id_rsa

# sed: used to perform an in-place replacement

# Replaces the line with "PasswordAuthentication yes," effectively enabling password authentication for SSH logins.
RUN sudo sed -i "s/^.*PasswordAuthentication.*$/PasswordAuthentication yes/" /etc/ssh/sshd_config

# Replaces the line with PermitRootLogin yes, effectively allowing the root user to log in directly via SSH.
RUN sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Replaces that line with "X11Forwarding yes," effectively enabling X11 /home/sysop/.seiscomp for SSH connections.
RUN sudo sed -i "s/^.*X11Forwarding.*$/X11Forwarding yes/" /etc/ssh/sshd_config

# Replaces that line with "X11UseLocalhost no," effectively disabling the use of localhost for X11 forwarding. 
RUN sudo sed -i "s/^.*X11UseLocalhost.*$/X11UseLocalhost no/" /etc/ssh/sshd_config

# It checks if a line starting with "X11UseLocalhost" exists in the /etc/ssh/sshd_config file. If such a line is found, it does nothing.
# If no matching line is found (i.e., the grep command returns no results), it appends "X11UseLocalhost no" to the end of the /etc/ssh/sshd_config file.
RUN sudo grep "^X11UseLocalhost" /etc/ssh/sshd_config || echo "X11UseLocalhost no" >> /etc/ssh/sshd_config

RUN sudo apt install net-tools tightvncserver novnc -y

ENV DEBIAN_FRONTEND noninteractive

RUN sudo apt update
RUN sudo DEBIAN_FRONTEND=noninteractive apt-get install -y keyboard-configuration
RUN sudo DEBIAN_FRONTEND=noninteractive apt-get install -y lightdm

RUN sudo apt install -y xfce4 xfce4-goodies

RUN export USER=sysop

# vncpasswd: reads the password from standard input (piped from echo) and writes the password to a file. In this case, it writes the password to $HOME/.vnc/passwd.
RUN mkdir $HOME/.vnc && echo "example\nexample\n" | vncpasswd > $HOME/.vnc/passwd && chmod 400 $HOME/.vnc/passwd

RUN echo "#!/bin/bash\nxrdb $HOME/.Xresources\nstartxfce4 &\nxfce4-terminal" > $HOME/.vnc/xstartup && chmod +x $HOME/.vnc/xstartup

ENV USER sysop

RUN echo 'alias scolv-gisola="scolv -d mysql://sysop:sysop@gisola-db/seiscomp"' >> ~/.bashrc

RUN wget http://old.kali.org/kali/pool/main/x/xfwm4/xfwm4_4.14.2-1_amd64.deb && sudo dpkg -i *.deb && rm *.deb

# Clean up (baseimage recommended)
# /var/lib/apt/lists/*: This directory contains cached information about available packages. Removing it ensures that the package cache is entirely cleaned.
# /tmp/*: This directory typically contains temporary files, and removing its contents helps free up disk space.
# /var/tmp/*: This directory is another location where temporary files are often stored, and removing its contents also helps free up disk space.
RUN sudo apt-get clean && sudo rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
