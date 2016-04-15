#!/bin/bash -ex
yum -y install wget git yum-utils createrepo gnupg2
cd /tmp
wget https://storage.googleapis.com/golang/go1.6.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
mkdir -p /opt/aptly
export GOPATH=/opt/aptly
go get -u github.com/mattn/gom
mkdir -p $GOPATH/src/github.com/smira/aptly
git clone -b master https://github.com/smira/aptly.git $GOPATH/src/github.com/smira/aptly
cd $GOPATH/src/github.com/smira/aptly
${GOPATH}/bin/gom -production install
${GOPATH}/bin/gom build -o $GOPATH/bin/aptly
cd /usr/bin
ln -s /opt/aptly/bin/aptly .
