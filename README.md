# BIND_Sinkhole

Bind Sinkhole from MISP - Docker Image (bind with dnstap enabled)

-- Luca Memini <luca.memini@leonardocompany.com>

Based on idea from two docker https://github.com/sameersbn/docker-bind and https://github.com/Benster900/ThunderLemon/ 
and sinkhole domain list from MISP https://github.com/MISP/MISP

:: For build

```
git clone https://github.com/LDO-CERT/bind_sinkhole
cd bind_sinkhole
docker build -t bind_sinkhole .
```

:: For run

```
docker run --name bind_sinkhole -d --restart=always \
  --publish 53:53/tcp --publish 53:53/udp \
  --volume /opt/bind_sinkhole:/data \
  bind_sinkhole
```

:: Persistence

For the BIND to preserve its state across container shutdown and startup you should mount a volume at /data.
SELinux users should update the security context of the host mountpoint so that it plays nicely with Docker:

```
mkdir -p /opt/bind_sinkhole
chcon -Rt svirt_sandbox_file_t /opt/bins_sinkhole
```

:: Sinkhole from MISP data

Edit conf/sinkhole/misp.config.dist before building docker images OR edit
/opt/bind_sinkhole/bind/etc/misp.config with your auth_key (from misp) and misp FQDN.


:: DNStap Reader

dnstap_reader contains developing software for read dnstap data (from file or socket)

 pip3 install protobuf
 pip3 install var_dump
 pip3 install daemonize
 pip3 install dnspython

