#!/bin/bash

fname="/etc/bind/named.conf.sinkhole"
fhash="/etc/bind/.named.conf.sinkhole.md5"

if [ ! -f $fhash ]; then
	if [ -f $fname ]; then
		md5sum $fname > $fhash
		rndc reload
	else
		echo "$fname not found"
		exit 1
	fi
fi

if ! md5sum --status -c $fhash; then
	logger -it "reload_bind" "$fname hash changed, reloading bind"
	diff -Nura /etc/bind/named.conf.sinkhole.save /etc/bind/named.conf.sinkhole
	md5sum $fname > $fhash
	/usr/sbin/named-checkconf
	if [ $? == 0 ]; then
		/usr/sbin/rndc reload
		/usr/sbin/rndc flush
	else
		logger -it "reload_bind" "ERROR: Invalid config file"
	fi
else
	logger -it "reload_bind" "nothing to do..."
	exit 0
fi

exit

