#!/bin/bash

mkdir -p /opt/bind_sinkhole
#chmod 777 -R /opt/bind_sinkhole

docker run --name bind_sinkhole \
  -d --restart=always \
  --publish 53:53/udp \
  --publish 53:53/tcp \
  --volume /opt/bind_sinkhole:/data \
  bind_sinkhole
