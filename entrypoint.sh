#!/bin/bash
set -e

BIND_DATA_DIR=${DATA_DIR}/bind
SSMTP_DATA_DIR=${DATA_DIR}/ssmtp

create_ssmtp_dir() {

  if [ ! -d /etc/ssmtp.old ]; then 
	  #mkdir -p ${SSMTP_DATA_DIR}

	  if [ ! -d ${SSMTP_DATA_DIR} ]; then
	    cp -r /etc/ssmtp/ ${SSMTP_DATA_DIR}
	  fi
	  mv /etc/ssmtp /etc/ssmtp.old
	  ln -sf ${SSMTP_DATA_DIR} /etc/ssmtp
  fi
}

create_bind_data_dir() {
  mkdir -p ${BIND_DATA_DIR}

  # populate default bind configuration if it does not exist
  if [ ! -d ${BIND_DATA_DIR}/etc ]; then
    mv /etc/bind ${BIND_DATA_DIR}/etc
  fi

#  if grep -q named.conf.sinkhole ${BIND_DATA_DIR}/etc/named.conf.local ; then
#	echo "found named.conf.sinkhole in ${BIND_DATA_DIR}/etc/named.conf.local" 
#  else
#	echo 'include "/etc/bind/named.conf.sinkhole";' >> ${BIND_DATA_DIR}/etc/named.conf.local
#  fi

  rm -rf /etc/bind
  ln -sf ${BIND_DATA_DIR}/etc /etc/bind
  chmod -R 0775 ${BIND_DATA_DIR}
  chown -R ${BIND_USER}:${BIND_USER} ${BIND_DATA_DIR}

  ln -sf ${BIND_DATA_DIR}/lib /var/lib/bind
}

create_pid_dir() {
  mkdir -m 0775 -p /var/run/named
  chown root:${BIND_USER} /var/run/named
}

create_bind_cache_dir() {
  mkdir -m 0775 -p /var/cache/bind /var/log/bind
  chown root:${BIND_USER} /var/cache/bind /var/log/bind

}

create_pid_dir
create_bind_data_dir
create_bind_cache_dir
create_ssmtp_dir

# allow arguments to be passed to named
if [[ ${1:0:1} = '-' ]]; then
  EXTRA_ARGS="$@"
  set --
elif [[ ${1} == named || ${1} == $(which named) ]]; then
  EXTRA_ARGS="${@:2}"
  set --
fi

# default behaviour is to launch named
if [[ -z ${1} ]]; then
  echo "Starting cron..."
  /etc/init.d/cron start

  echo "Starting named..."
  exec $(which named) -u ${BIND_USER} -g ${EXTRA_ARGS}
else
  exec "$@"
fi

