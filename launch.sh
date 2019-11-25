set -x
docker-compose up -d db-next
docker-compose up -d openldap
sleep 2
docker-compose up -d next
