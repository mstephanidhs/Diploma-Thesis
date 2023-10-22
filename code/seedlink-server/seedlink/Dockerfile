# -*- coding: utf-8 -*-
# Basic Dockerfile to run ringserver in a container
# sets the base image for the Docker container to Ubuntu 20.04
FROM ubuntu:20.04

# Install 'gcc' and 'make' packages
RUN apt-get update -y && apt install -y gcc make

# Build executable
# sets the working directory within the container
WORKDIR /seedlink
#RUN mkdir /seedlink

# copies the contents of your current directory into the 
# '/seedlink' directory within the container
COPY . /seedlink

# using the 'make' command (compilation) with certain compilation flags
RUN cd /seedlink && CFLAGS="-O2" make

# create a user and group named "sysop" within the container
# the user is also added to the "sudo" group
RUN groupadd sysop
RUN useradd -rm -d /home/sysop -s /bin/bash -g sysop -G sudo -u 1001 sysop -p sysop

# removes the password for the sysop user
RUN passwd -d sysop

# subsequents commands will be executed as the "sysop" user
USER sysop
# changes the working directory
WORKDIR /home/sysop

# exposes port 18000 from the container to the host machine, in order to allow external 
# access to a service running inside the container on that port
# Expose default SeedLink and DataLink ports
EXPOSE 18000
#EXPOSE 16000

# changes the working directory back to '/seedlink'
WORKDIR /seedlink

COPY ./protocols /etc/protocols

# set the default command to run when the container starts
# Default command is "ringserver"
ENTRYPOINT [ "./ringserver" ]

# basically, runs the "ringserver" with the argument "ring.conf"
# Default arguments
CMD [ "./ring.conf"]
