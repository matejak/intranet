set -e

export DOMAINNAME=localhost
export ADMIN_PASSWORD=none

. provision.sh

set -x

docker compose up -d openldap
docker compose up -d mongo-rocket
docker compose up -d db-next db-keycloak db-redmine

docker compose up -d --wait mongo-rocket

configure_mongo

docker compose up -d next

docker compose up -d --wait db-keycloak

docker compose up -d keycloak

configure_ldap_acl

docker compose up -d --wait next

configure_nextcloud
configure_nextcloud_ldap

docker compose up -d rocketchat

# configure_bureau_saml_except_certs
# docker compose up -d bureau

docker compose up -d --wait keycloak

configure_keycloak_next
# configure_keycloak_bureau
configure_keycloak_ldap
configure_keycloak_rocketchat
configure_keycloak_redmine

# configure_bureau_saml_certs

configure_rocketchat_general
configure_rocketchat_ldap
configure_rocketchat_saml_except_certs
configure_rocketchat_saml_certs

configure_nextcloud_saml_except_certs
configure_nextcloud_saml_certs

configure_redmine_saml
docker compose up -d redmine

docker compose up -d gateway
docker compose restart gateway

# bureau_exec_flask bootstrap

# docker compose restart bureau

docker compose restart gateway

echo Now generate an invite link for an admin user of a username of your choice:
echo 'docker compose exec bureau flask invite-admin-user <username>'
