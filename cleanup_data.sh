SCRIPT_DIR="$(dirname $0)"
cd "$SCRIPT_DIR"

docker compose rm -s -f openldap keycloak db-keycloak next db-next db-redmine redmine rocketchat mongo-rocket
sudo rm -rf data/ldap data/keycloak data/next data/rocket data/redmine data/bureau/settings.json
mkdir -p data/ldap data/keycloak data/next data/rocket data/redmine
