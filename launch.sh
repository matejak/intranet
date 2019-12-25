#!/bin/bash


set -ex
docker-compose up -d db-next
docker-compose up -d mongo-rocket
docker-compose up -d openldap
sleep 15 &

. "$(dirname "${BASH_SOURCE[0]}")/provision.sh"
configure_rocketchat

(cd build/teap && git fetch origin && git checkout master && git pull)
docker-compose build teap
wait

docker-compose up -d rocketchat
docker-compose up -d next
docker-compose up -d teap
