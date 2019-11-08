DOMAINNAME='entint.org'
ADMIN_PASSWORD='admin'
ADMIN_USER='admin'

SSO_HOSTNAME='sso'
NEXTCLOUD_HOSTNAME='next'
ROCKETCHAT_HOSTNAME='rocket'
COLLABORA_HOSTNAME='collabora'
MAIL_SUBDOMAIN=mail

MAIL_HOST=$DOMAINNAME
test -n "$MAIL_SUBDOMAIN" && MAIL_HOST="$MAIL_SUBDOMAIN.$MAIL_HOST"

# yes if we are testing things locally, i.e. without a real domain
LOCAL_SETUP=yes

readarray -d . -t DOMAIN_COMPONENTS <<< "$DOMAINNAME"
LDAP_BASE_DN=
for dc in "${DOMAIN_COMPONENTS[@]}"; do
	LDAP_BASE_DN="${LDAP_BASE_DN}dc=$dc,"
done
# Trim the last comma
LDAP_BASE_DN="${LDAP_BASE_DN: : -1}"


declare -A LDAP_CONFIGURATION
LDAP_CONFIGURATION["lastJpegPhotoLookup"]="0"
LDAP_CONFIGURATION["ldapAgentName"]="cn=$ADMIN_USER,$LDAP_BASE_DN"
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
SAML_CONFIGURATION["idp-entityId"]="https://$SSO_HOSTNAME.$DOMAINNAME/auth/realms/master"
SAML_CONFIGURATION["idp-singleSignOnService.url"]="https://$SSO_HOSTNAME.$DOMAINNAME/auth/realms/master/protocol/saml"
SAML_CONFIGURATION["type"]="saml"
SAML_CONFIGURATION["general-idp0_display_name"]="SAMLLogin"
SAML_CONFIGURATION["general-allow_multiple_user_back_ends"]="1"

# Service Provider certificate and key - That's us, Nextcloud
SAML_CONFIGURATION["sp-privateKey"]=""
SAML_CONFIGURATION["sp-x509cert"]=""

SAML_CONFIGURATION["saml-attribute-mapping-email_mapping"]=""
SAML_CONFIGURATION["idp-singleLogoutService.url"]="https://$SSO_HOSTNAME.$DOMAINNAME/auth/realms/master/protocol/saml"
SAML_CONFIGURATION["security-authnRequestsSigned"]="1"
SAML_CONFIGURATION["security-logoutRequestSigned"]="1"
SAML_CONFIGURATION["security-logoutResponseSigned"]="1"
SAML_CONFIGURATION["security-wantMessagesSigned"]="1"
SAML_CONFIGURATION["security-wantAssertionsSigned"]="1"
SAML_CONFIGURATION["saml-attribute-mapping-displayName_mapping"]=""
SAML_CONFIGURATION["general-require_provisioned_account"]="1"

# Identity Provider certificate - That's Keycloak
SAML_CONFIGURATION["idp-x509cert"]=""


declare -A OFFICE_CONFIGURATION
OFFICE_CONFIGURATION["wopi_url"]="https://$COLLABORA_HOSTNAME.$DOMAINNAME"
OFFICE_CONFIGURATION["public_wopi_url"]="${OFFICE_CONFIGURATION[wopi_url]}"


declare -A MAIL_CONFIGURATION
MAIL_CONFIGURATION["email"]="%USERID%@$MAIL_HOST"
MAIL_CONFIGURATION["imapHost"]="$MAIL_HOST"
MAIL_CONFIGURATION["imapPort"]=143
MAIL_CONFIGURATION["imapSslMode"]="tls"
MAIL_CONFIGURATION["imapUser"]="%USERID%@$DOMAINNAME"
MAIL_CONFIGURATION["smtpHost"]="$MAIL_HOST"
MAIL_CONFIGURATION["smtpPort"]=587
MAIL_CONFIGURATION["smtpSslMode"]="tls"
MAIL_CONFIGURATION["smtpUser"]="%USERID%@$DOMAINNAME"


function nextcloud_exec {
	docker-compose exec --user www-data next php occ --no-ansi "$@"
}


function keycloak_exec {
	docker-compose exec keycloak '/opt/jboss/keycloak/bin/kcadm.sh' "$@"
}


function apps_enable {
	for app in "$@"; do
		nextcloud_exec "app:install" "$app"
		nextcloud_exec "app:enable" "$app"
	done
}


function ldap_has_config {
	out=$(nextcloud_exec ldap:show-config)
	test -n "$out" && return 0 || return 1
}


function ldap_config_id {
	out=$(nextcloud_exec ldap:show-config)
	printf "%s" "$(grep '\<Configuration\>' <<< "${out}" | cut -f 3 -d '|' | tr -d '[:blank:]')"
}


function configure_office {
	for item in "${!OFFICE_CONFIGURATION[@]}"; do
		nextcloud_exec "config:app:set" --value "${OFFICE_CONFIGURATION[$item]}" richdocuments "$item"
	done
}


function configure_nextcloud {
	apps_enable groupfolders user_ldap user_saml richdocuments mail
	test "$LOCAL_SETUP" = yes || nextcloud_exec "config:system:set" --value "https" "overwriteprotocol"
	for item in "${!MAIL_CONFIGURATION[@]}"; do
		nextcloud_exec "config:system:set" --value "${MAIL_CONFIGURATION[$item]}" app.mail.accounts.default "$item"
	done
}


function configure_ldap {
	if ldap_has_config; then
		c_id=$(ldap_config_id)
	else
		out=$(nextcloud_exec 'ldap:create-empty-config')
		c_id=$(sed -e 's/.*configID\s*//' <<< "$out")
	fi

	for item in "${!LDAP_CONFIGURATION[@]}"; do
		nextcloud_exec "ldap:set-config" "$c_id" "$item" "${LDAP_CONFIGURATION[$item]}"
	done
}


function configure_saml_except_certs {
	for item in "${!SAML_CONFIGURATION[@]}"; do
		grep -q 'x509cert' <<< $item && continue
		grep -q 'privateKey' <<< $item && continue
		nextcloud_exec "config:app:set" --value "${SAML_CONFIGURATION[$item]}" user_saml "$item"
	done
}


function _keycloak_client_id {
	printf "%s" "$(keycloak_exec get clients -q "clientId=https://$NEXTCLOUD_HOSTNAME.$DOMAINNAME/apps/user_saml/saml/metadata" -F id | jq -M --raw-output '.[0].id')"
}


function configure_keycloak {
	keycloak_exec config credentials --server http://localhost:8080/auth --realm master --user "$ADMIN_USER" --password $ADMIN_PASSWORD
	client_id=$(_keycloak_client_id)
	if test "$client_id" = null; then
		echo 'ERRORRE!'
	fi
        keycloak_exec update "clients/$client_id" -s 'attributes."saml.signing.certificate"=haha'
	# TODO: Create the Nextcloud client by downloading its SAML metadata and supplying it to the API
	# TODO: get the mappings, set mappings and uniqueness and whatever.
}


function configure_saml_certs {
	tmp_dir=$(mktemp -d -t certs-XXXXXX)
	sp_cert="$tmp_dir/myservice.key"
	sp_key="$tmp_dir/myservice.cert"
	idp_cert="$tmp_dir/myidp.cert"
	openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -batch -keyout "$sp_cert" -out "$sp_key"
	client_id=$(_keycloak_client_id)
        keycloak_exec update "clients/$client_id" -s 'attributes."saml.signing.certificate"='"$(cat "$sp_cert" | head -n -1 | tail -n +2)"
	nextcloud_exec "config:app:set" --value="$(cat "$sp_cert")" user_saml "sp-x509cert"
	nextcloud_exec "config:app:set" --value="$(cat "$sp_key")" user_saml "sp-privateKey"
	rm -f "$sp_cert" "$sp_key"
	printf '%s\n' '-----BEGIN CERTIFICATE-----' > "$idp_cert"
	keycloak_realm_cert=$(keycloak_exec get realms/master/keys -F 'keys(publicKey)' | jq -M --raw-output 'flatten|add.publicKey')
	printf '%s\n' "$keycloak_realm_cert" >> "$idp_cert"
	printf '%s\n' '-----END CERTIFICATE-----' >> "$idp_cert"
	nextcloud_exec "config:app:set" --value="$(cat "$idp_cert")" user_saml "idp-x509cert"
	rm -f "$idp_cert"
	rm -rf "$tmp_dir"
}


function substitute_env_vars_in_file {
	readarray envs -t < <(set | grep '^[A-Z_]\+=[^(]')
	for env_line in "${envs[@]}"; do
		varname=$(cut -f 1 -d = <<< "$env_line")
		value=$(cut -f 1 -d = --complement <<< "$env_line")
		sed -i "s|@$varname@|$value|g" "$1"
	done
}


function create_nginx_conf {
	cp config/nginx.conf.in config/nginx.conf
	substitute_env_vars_in_file "config/nginx.conf"
}

# configure_nextcloud
# configure_ldap
# configure_saml_except_certs
# configure_keycloak
# configure_saml_certs
