docker-compose stop next db-next
docker-compose rm -f next db-next
rm -rf data/next
mkdir -p data/next

docker-compose stop rocketchat mongo-rocket
docker-compose rm -f rocketchat mongo-rocket
rm -rf data/rocket
mkdir -p data/rocket

docker-compose stop openldap
docker-compose rm -f openldap
rm -rf data/ldap
mkdir -p data/ldap

docker-compose stop teap
docker-compose rm -f teap
