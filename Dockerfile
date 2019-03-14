FROM ubuntu:18.04

MAINTAINER "luca.memini@leonardocompany.com"
LABEL Version="1.1"
LABEL Description="Bind Sinkhole from MISP Docker Image (dnstap enabled)"

ENV BIND_USER=bind \
    DATA_DIR=/data

ENV DEBIAN_FRONTEND noninteractive

## 1/ Minimal ubuntu install

RUN echo "deb-src http://it.archive.ubuntu.com/ubuntu/ bionic main universe restricted multiverse" >> /etc/apt/sources.list.d/src.list
RUN echo "deb-src http://security.ubuntu.com/ubuntu bionic-security main universe restricted multiverse" >> /etc/apt/sources.list.d/src.list
RUN echo "deb-src http://it.archive.ubuntu.com/ubuntu/ bionic-updates main universe restricted multiverse" >> /etc/apt/sources.list.d/src.list

# Upgrade system
RUN \
  apt-get update && \
  apt-get dist-upgrade -y --no-install-recommends && \
  apt-get autoremove -y && \
  apt-get clean 

# Avoid ERROR: invoke-rc.d: policy-rc.d denied execution of start.
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

RUN apt install build-essential gcc git net-tools libssl-dev libprotobuf-c0-dev protobuf-c-compiler dh-autoreconf pkg-config libevent-dev libxml2 libxml2-dev haveged \
	libjson-c-dev gnupg wget dh-exec libkrb5-dev libdb-dev libcap2-dev libgeoip-dev dh-systemd dh-autoreconf bison dh-apparmor dh-python libldap2-dev \
	libprotobuf-dev python3-ply -y

# Compile FSTRM
RUN git clone https://github.com/farsightsec/fstrm.git /tmp/fstrm
RUN cd /tmp/fstrm && ./autogen.sh && cd /tmp/fstrm && ./configure && cd /tmp/fstrm && make && cd /tmp/fstrm && make install
RUN ldconfig

# Re-Compile bind9 with dnstap enabled and install it from deb
RUN cd /tmp && apt-get source bind9 
RUN cd /tmp/bind9* && sed -i -e 's/export DPKG_GENSYMBOLS_CHECK_LEVEL := 4/#export DPKG_GENSYMBOLS_CHECK_LEVEL := 4/g' debian/rules
RUN cd /tmp/bind9* && sed -i -e 's/dh_auto_configure -B build -- /dh_auto_configure -B build -- --enable-dnstap /g' debian/rules
RUN cd /tmp/bind9* && sed -i -e 's/$(PROTOC_C) --c_out=. dnstap.proto/$(PROTOC_C) --c_out=. --proto_path ${srcdir} ${srcdir}\/dnstap.proto/g' lib/dns/Makefile.in
RUN cd /tmp/bind9* && sed -i -e $'s/.PHONY: prepare_native_pkcs11 clean_native_pkcs11/override_dh_shlibdeps:\n\tdh_shlibdeps --dpkg-shlibdeps-params=--ignore-missing-info\n\n.PHONY: prepare_native_pkcs11 clean_native_pkcs11/g' debian/rules
RUN cd /tmp/bind9* && sed -i -e $'s/\/\/ dnstap: flexible, structured event replication format for DNS software/syntax="proto2";\n\/\/ dnstap: flexible, structured event replication format for DNS software/g' lib/dns/dnstap.proto
RUN cd /tmp/bind9* && sed -i -e $'s/tsig-keygen.8/tsig-keygen.8\nusr\/share\/man\/man1\/dnstap-read.1\nusr\/bin\/dnstap-read/g'  debian/bind9.install
RUN cd /tmp/bind9* && cat debian/rules
RUN cd /tmp/bind9* && dpkg-buildpackage -b && ls -al /tmp/*.deb
RUN cd /tmp/ && dpkg -i  bind9_9*.deb \
	bind9utils_9*.deb \
	dnsutils_9*.deb \
	bind9-host_9*.deb \
	libirs160_9*.deb \
	libbind9-160_9*.deb \
	libdns1100_9*.deb \
	libisc169_9*.deb \
	libisccc160_9*.deb \
	libisccfg160_9*.deb \
	liblwres160_9*.deb

RUN apt-get -fy install 

# Copy named.conf.options
COPY conf/bind/named.conf.options /etc/bind/named.conf.options

RUN \
  apt-get install -y --no-install-recommends nano screen wget supervisor curl language-pack-en && \
  apt-get clean

## 2/ Dependencies

RUN echo "Installing dependecies"
RUN apt-get install -y cron ssmtp dnstap-ldns
RUN apt-get clean

## 3/ bind_sinkhole code

COPY conf/bind/blockeddomains.db /etc/bind/blockeddomains.db
COPY conf/bind/named.conf.sinkhole /etc/bind/named.conf.sinkhole
COPY conf/bind/named.conf.local /etc/bind/named.conf.local

RUN mkdir -p /home/bind_sinkhole
COPY scripts/export_host.sh /home/bind_sinkhole/export_host.sh
COPY scripts/reload_bind.sh /home/bind_sinkhole/reload_bind.sh
RUN chmod +x /home/bind_sinkhole/*.sh

COPY conf/sinkhole/sinkhole.cron.d /etc/cron.d/bind_sinkhole
COPY conf/sinkhole/misp.config.dist /etc/bind/misp.config

COPY entrypoint.sh /sbin/entrypoint.sh
RUN chmod +x /sbin/entrypoint.sh

EXPOSE 53/udp 53/tcp 

ENTRYPOINT ["/sbin/entrypoint.sh"]

CMD ["/usr/sbin/named"]
