DOMAINNAME=entint.org
ADMIN_PASSWORD=admin
LDAP_BASE_DN='dc=entint,dc=org'

declare -A LDAP_CONFIGURATION
LDAP_CONFIGURATION["lastJpegPhotoLookup"]="0"
LDAP_CONFIGURATION["ldapAgentName"]="cn=admin,$LDAP_BASE_DN"
LDAP_CONFIGURATION["ldapAgentPassword"]="$ADMIN_PASSWORD"
LDAP_CONFIGURATION["ldapAttributesForGroupSearch"]="cn;description"
LDAP_CONFIGURATION["ldapBase"]="$LDAP_BASE_DN"
LDAP_CONFIGURATION["ldapBaseGroups"]="$LDAP_BASE_DN"
LDAP_CONFIGURATION["ldapBaseUsers"]="ou=people,$LDAP_BASE_DN"
LDAP_CONFIGURATION["ldapCacheTTL"]="600"
LDAP_CONFIGURATION["ldapConfigurationActive"]="1"
LDAP_CONFIGURATION["ldapEmailAttribute"]="mail"
LDAP_CONFIGURATION["ldapExperiencedAdmin"]="0"
LDAP_CONFIGURATION["ldapExpertUsernameAttr"]="uid"
LDAP_CONFIGURATION["ldapGidNumber"]="gidNumber"
LDAP_CONFIGURATION["ldapGroupDisplayName"]="description"
LDAP_CONFIGURATION["ldapGroupFilter"]="(&(|(objectclass=posixGroup)))"
LDAP_CONFIGURATION["ldapGroupFilterMode"]="1"
LDAP_CONFIGURATION["ldapGroupMemberAssocAttr"]="memberUid"
LDAP_CONFIGURATION["ldapHost"]="ldap"
LDAP_CONFIGURATION["ldapLoginFilter"]="(&(|(objectclass=inetOrgPerson))(uid=%uid))"
LDAP_CONFIGURATION["ldapLoginFilterEmail"]="0"
LDAP_CONFIGURATION["ldapLoginFilterMode"]="0"
LDAP_CONFIGURATION["ldapLoginFilterUsername"]="1"
LDAP_CONFIGURATION["ldapNestedGroups"]="0"
LDAP_CONFIGURATION["ldapPagingSize"]="500"
LDAP_CONFIGURATION["ldapPort"]="389"
LDAP_CONFIGURATION["ldapTLS"]="0"
LDAP_CONFIGURATION["ldapUserAvatarRule"]="default"
LDAP_CONFIGURATION["ldapUserDisplayName"]="cn"
LDAP_CONFIGURATION["ldapUserFilter"]="(|(objectclass=inetOrgPerson))"
LDAP_CONFIGURATION["ldapUserFilterMode"]="0"
LDAP_CONFIGURATION["ldapUserFilterObjectclass"]="inetOrgPerson"
LDAP_CONFIGURATION["ldapUuidGroupAttribute"]="auto"
LDAP_CONFIGURATION["ldapUuidUserAttribute"]="auto"
LDAP_CONFIGURATION["turnOffCertCheck"]="0"
LDAP_CONFIGURATION["turnOnPasswordChange"]="0"
LDAP_CONFIGURATION["useMemberOfToDetectMembership"]="1"

declare -A SAML_CONFIGURATION
SAML_CONFIGURATION["general-uid_mapping"]="username"
SAML_CONFIGURATION["idp-entityId"]="https://sso.$DOMAINNAME/auth/realms/master"
SAML_CONFIGURATION["idp-singleSignOnService.url"]="https://sso.$DOMAINNAME/auth/realms/master/protocol/saml"
SAML_CONFIGURATION["type"]="saml"
SAML_CONFIGURATION["general-idp0_display_name"]="SAMLLogin"
SAML_CONFIGURATION["general-allow_multiple_user_back_ends"]="1"
# Service Provider - That's us

SAML_CONFIGURATION["sp-privateKey"]=""
SAML_CONFIGURATION["sp-x509cert"]=""

SAML_CONFIGURATION["saml-attribute-mapping-email_mapping"]=""
SAML_CONFIGURATION["idp-singleLogoutService.url"]="https://sso.$DOMAINNAME/auth/realms/master/protocol/saml"
SAML_CONFIGURATION["security-authnRequestsSigned"]="1"
SAML_CONFIGURATION["security-logoutRequestSigned"]="1"
SAML_CONFIGURATION["security-logoutResponseSigned"]="1"
SAML_CONFIGURATION["security-wantMessagesSigned"]="1"
SAML_CONFIGURATION["security-wantAssertionsSigned"]="1"
SAML_CONFIGURATION["saml-attribute-mapping-displayName_mapping"]=""
# Service Provider - That's Keycloak

SAML_CONFIGURATION["idp-x509cert"]=""

SAML_CONFIGURATION["general-require_provisioned_account"]="1"

declare -A OFFICE_CONFIGURATION
OFFICE_CONFIGURATION["wopi_url"]="https://collabora.cspii.org"
OFFICE_CONFIGURATION["public_wopi_url"]="${OFFICE_CONFIGURATION[wopi_url]}"

declare -A MAIL_CONFIGURATION
MAIL_CONFIGURATION["email"]="%USERID%@mail.cspii.org"
MAIL_CONFIGURATION["imapHost"]="mail.cspii.org"
MAIL_CONFIGURATION["imapPort"]=143
MAIL_CONFIGURATION["imapSslMode"]="tls"
MAIL_CONFIGURATION["imapUser"]="%USERID%@cspii.org"
MAIL_CONFIGURATION["smtpHost"]="mail.cspii.org"
MAIL_CONFIGURATION["smtpPort"]=587
MAIL_CONFIGURATION["smtpSslMode"]="tls"
MAIL_CONFIGURATION["smtpUser"]="%USERID%@cspii.org"

set -x
# LDAP_CONFIGURATION

function nex {
	docker-compose exec --user www-data next php occ --no-ansi "$@"
}

function kex {
	docker-compose exec keycloak '/opt/jboss/keycloak/bin/kcadm.sh' "$@"
}

function apps_enable {
	for app in "$@"; do
		nex "app:install" "$app"
		nex "app:enable" "$app"
	done
}


function ldap_has_config {
	out=$(nex ldap:show-config)
	test -n "$out" && return 0 || return 1
}


function ldap_config_id {
	out=$(nex ldap:show-config)
	printf "%s" "$(grep '\<Configuration\>' <<< "${out}" | cut -f 3 -d '|' | tr -d '[:blank:]')"
}


function configure_office {
	for item in "${!OFFICE_CONFIGURATION[@]}"; do
		nex "config:app:set" --value "${OFFICE_CONFIGURATION[$item]}" richdocuments "$item"
	done
}


function configure_nextcloud {
	apps_enable groupfolders user_ldap user_saml richdocuments mail
	# nex "config:system:set" --value "https" "overwriteprotocol"
	for item in "${!MAIL_CONFIGURATION[@]}"; do
		nex "config:system:set" --value "${MAIL_CONFIGURATION[$item]}" app.mail.accounts.default "$item"
	done
}


function configure_ldap {
	if ldap_has_config; then
		c_id=$(ldap_config_id)
	else
		out=$(nex 'ldap:create-empty-config')
		c_id=$(sed -e 's/.*configID\s*//' <<< "$out")
	fi

	for item in "${!LDAP_CONFIGURATION[@]}"; do
		nex "ldap:set-config" "$c_id" "$item" "${LDAP_CONFIGURATION[$item]}"
	done
}

function configure_saml_except_certs {
	for item in "${!SAML_CONFIGURATION[@]}"; do
		grep -q 'x509cert' <<< $item && continue
		grep -q 'privateKey' <<< $item && continue
		nex "config:app:set" --value "${SAML_CONFIGURATION[$item]}" user_saml "$item"
	done
}


function _keycloak_client_id {
	printf "%s" "$(kex get clients -q clientId=https://next.$DOMAINNAME/apps/user_saml/saml/metadata -F id | jq -M --raw-output '.[0].id')"
}


function configure_keycloak {
	# download the SAML metadata at: https://next.$DOMAINNAME/apps/user_saml/saml/metadata
	# kex config credentials --server http://localhost:8080/auth --realm master --user admin --password $ADMIN_PASSWORD
	kex config credentials --server http://localhost:8080/auth --realm master --user admin --password $ADMIN_PASSWORD
	client_id=$(_keycloak_client_id)
	if test "$client_id" = null; then
		echo 'ERRORRE!'
	fi
        kex update "clients/$client_id" -s 'attributes."saml.signing.certificate"=haha'
	# get the mappings, set mappings and uniqueness and whatever.
	# kex update "clients/$client_id" -s 'attributes."saml.authnstatement"=true'
	# The client should be created manually.
	# kex update clients/b25125a4-3b70-40af-a36b-ab5012e5a029 -s 'attributes."saml.authnstatement"=true'
}


function configure_cert {
	openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -batch -keyout /tmp/myservice.key -out /tmp/myservice.cert
	client_id=$(_keycloak_client_id)
        kex update "clients/$client_id" -s 'attributes."saml.signing.certificate"='"$(cat /tmp/myservice.cert | head -n -1 | tail -n +2)"
	nex "config:app:set" --value="$(cat /tmp/myservice.cert)" user_saml "sp-x509cert"
	nex "config:app:set" --value="$(cat /tmp/myservice.key)" user_saml "sp-privateKey"
	rm -f /tmp/myservice.key /tmp/myservice.cert
	printf '%s\n' '-----BEGIN CERTIFICATE-----' > /tmp/myidp.cert
	keycloak_realm_cert=$(kex get realms/master/keys -F 'keys(publicKey)' | jq -M --raw-output 'flatten|add.publicKey')
	printf '%s\n' "$keycloak_realm_cert" >> /tmp/myidp.cert
	printf '%s\n' '-----END CERTIFICATE-----' >> /tmp/myidp.cert
	nex "config:app:set" --value="$(cat /tmp/myidp.cert)" user_saml "idp-x509cert"
	rm -f myidp.cert
}

# configure_nextcloud
# configure_ldap
# configure_saml_except_certs
# configure_keycloak
# configure_cert
