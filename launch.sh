#!/bin/bash

INTRANET_REPO=https://github.com/EnterpriseyIntranet/intranet.git

set -ex
docker-compose up -d db-next
docker-compose up -d mongo-rocket
docker-compose up -d openldap
sleep 15 &

. "$(dirname "${BASH_SOURCE[0]}")/provision.sh"
configure_rocketchat

(file -d build/teap || { cd build && git clone "$INTRANET_REPO"; } )
(cd build/teap && git fetch origin && git pull)
docker-compose build teap
wait

docker-compose up -d rocketchat
docker-compose up -d next
docker-compose up -d teap
