FROM centos:7
MAINTAINER Alan Franzoni <username@franzoni.eu>
ADD build.sh /tmp/
RUN /tmp/build.sh
