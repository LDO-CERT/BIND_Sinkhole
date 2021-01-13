#!/bin/bash

source /etc/bind/misp.config

# non toccare!! :-)
DOMAIN_URL="/attributes/text/download/domain"
### Domain URL withtout domain in warninglist
DOMAIN_URL="/attributes/text/download/domain/null/null/null/null/null/null/true"

PCOUNT=`pgrep -xc export_host.sh`

if [ "$PCOUNT" -gt "1" ]; then
        logger -it misp_exporter "Alredy running";
else
        if [ -z $AUTH_KEY ]; then
                logger -it misp_exporter "Disabled";
                exit 0;
        else
                #curl -v -H "Authorization: $AUTH_KEY" -H "Accept: application/json" -H "Content-Type: application/json" $HOST/events/1
                domain=`curl -k -s -H "Authorization: $AUTH_KEY" -H "Accept: application/json" -H "Content-Type: application/json" $HOST$DOMAIN_URL | sort | uniq`
        fi

        tot=0;

        echo "" > /etc/bind/named.conf.sinkhole.swp

        for i in $domain; do
                echo "zone \"$i\" {type master; notify no; file \"/etc/bind/blockeddomains.db\";};" >> /etc/bind/named.conf.sinkhole.swp
                tot=$((tot+1))
        done

        logger -it misp_exporter "Exported $tot domains";

        cp /etc/bind/named.conf.sinkhole /etc/bind/named.conf.sinkhole.save
        mv /etc/bind/named.conf.sinkhole.swp /etc/bind/named.conf.sinkhole

fi

