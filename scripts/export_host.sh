#!/bin/bash

source /etc/bind/misp.config

# non toccare!! :-)
DOMAIN_URL="/attributes/text/download/domain"
### Domain URL withtout domain in warninglist
DOMAIN_URL="/attributes/text/download/domain/null/null/null/null/null/null/true"

DEST_FILE="/etc/bind/sinkhole.db"


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

        echo "" > $DEST_FILE.swp
	echo '
$TTL    604800
@       IN      SOA     localhost. root.localhost. (
                          2         ; Serial
                     604800         ; Refresh
                      86400         ; Retry
                    2419200         ; Expire
                     604800 )       ; Negative Cache TTL

@       IN      NS      localhost.' > $DEST_FILE.swp


        for i in $domain; do
#                echo "zone \"$i\" {type master; notify no; file \"/etc/bind/blockeddomains.db\";};" >> $DEST_FILE.swp
	        echo "$i A 127.0.0.2"  >> $DEST_FILE.swp
	        echo "*.$i A 127.0.0.2"  >> $DEST_FILE.swp
                tot=$((tot+1))
        done

        logger -it misp_exporter "Exported $tot domains";

        cp $DEST_FILE $DEST_FILE.save
        mv $DEST_FILE.swp $DEST_FILE

fi

