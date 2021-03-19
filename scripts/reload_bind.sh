#!/bin/bash

#fname="/etc/bind/named.conf.sinkhole"
#fhash="/etc/bind/.named.conf.sinkhole.md5"
fname="/etc/bind/sinkhole.db"
fhash="/etc/bind/sinkhole.db.md5"

if [ ! -f $fhash ]; then
        if [ -f $fname ]; then
                md5sum $fname > $fhash
                /usr/sbin/rndc reload sinkhole 1>/dev/null 2>/dev/null
        else
                echo "$fname not found"
                exit 1
        fi
fi

if ! md5sum --status -c $fhash; then
        logger -it "reload_bind" "$fname hash changed"
        # diff -Nura /etc/bind/named.conf.sinkhole.save /etc/bind/named.conf.sinkhole
        md5sum $fname > $fhash

        #/usr/sbin/named-checkconf
        ERR=`/usr/sbin/named-checkconf -z 1>/dev/null`
        if [ $? == 0 ]; then
                logger -it "reload_bind" "Reloading bind server with new fresh zones"
        else
                 #/usr/sbin/named-checkconf -z | grep -v loaded
                echo $ERR
                logger -it "reload_bind" "WARNING: Error are present in config file, reloading could have problems"
        fi
        /usr/sbin/rndc reload sinkhole 1>/dev/null 2>/dev/null
        /usr/sbin/rndc flush
else
        logger -it "reload_bind" "nothing to do..."
        exit 0
fi

exit
