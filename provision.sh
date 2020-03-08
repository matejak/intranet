#!/bin/bash

DOMAINNAME="${DOMAINNAME:-entint.org}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
ADMIN_USER='admin'

SSO_HOSTNAME='sso'
NEXTCLOUD_HOSTNAME="${NEXTCLOUD_HOSTNAME:-next}"
ROCKETCHAT_HOSTNAME="${ROCKETCHAT_HOSTNAME:-rocket}"
TEAP_HOSTNAME="${TEAP_HOSTNAME:-teap}"
COLLABORA_HOSTNAME="${COLLABORA_HOSTNAME:-collabora}"
MAIL_SUBDOMAIN=mail

MAIL_HOST=$DOMAINNAME
test -n "$MAIL_SUBDOMAIN" && MAIL_HOST="$MAIL_SUBDOMAIN.$MAIL_HOST"

# yes if we are testing things locally, i.e. without a real domain
LOCAL_SETUP="${LOCAL_SETUP:-yes}"


function define_domain_components {
	local IFS='.'
	DOMAIN_COMPONENTS=()
	for dc in $DOMAINNAME; do
		DOMAIN_COMPONENTS+=("$dc")
	done
}


function escape_newlines {
	awk '{printf "%s\\n", $0}' <<< "$1" | sed -e 's/\\n$//'  # Remove the trailing '\n'
}


define_domain_components
# Requires Bash 4.4 or something.
# readarray -d . -t DOMAIN_COMPONENTS <<< "$DOMAINNAME"
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


declare -A CALENDAR_CONFIGURATION
CALENDAR_CONFIGURATION["sendEventRemindersPush"]="yes"
CALENDAR_CONFIGURATION["generateBirthdayCalendar"]="no"
CALENDAR_CONFIGURATION["sendInvitations"]="yes"
CALENDAR_CONFIGURATION["sendEventReminders"]="yes"


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


declare -A MONGO_LDAP
MONGO_LDAP[Authentication]='true'
MONGO_LDAP[Authentication_Password]="\"$ADMIN_PASSWORD\""
MONGO_LDAP[Authentication_UserDN]="\"cn=$ADMIN_USER,$LDAP_BASE_DN\""
MONGO_LDAP[Background_Sync]='true'
MONGO_LDAP[Background_Sync_Import_New_Users]='true'
MONGO_LDAP[Background_Sync_Interval]='"Every 2 hours"'
MONGO_LDAP[Background_Sync_Keep_Existant_Users_Updated]='true'
MONGO_LDAP[BaseDN]="\"ou=people,$LDAP_BASE_DN\""
MONGO_LDAP[CA_Cert]='""'
MONGO_LDAP[Connect_Timeout]='1000'
MONGO_LDAP[Default_Domain]="\"$DOMAINNAME\""
MONGO_LDAP[Enable]='true'
MONGO_LDAP[Encryption]='"plain"'
MONGO_LDAP[Find_User_After_Login]='true'
MONGO_LDAP[Group_Filter_Enable]='false'
MONGO_LDAP[Group_Filter_Group_Id_Attribute]='"cn"'
MONGO_LDAP[Group_Filter_Group_Member_Attribute]='"uniqueMember"'
MONGO_LDAP[Group_Filter_Group_Member_Format]='"uniqueMember"'
MONGO_LDAP[Group_Filter_Group_Name]='"ROCKET_CHAT"'
MONGO_LDAP[Group_Filter_ObjectClass]='"posixGroup"'
MONGO_LDAP[Host]='"ldap"'
MONGO_LDAP[Idle_Timeout]='1000'
MONGO_LDAP[Internal_Log_Level]='"disabled"'
MONGO_LDAP[Login_Fallback]='true'
MONGO_LDAP[Merge_Existing_Users]='true'
MONGO_LDAP[Port]='"389"'
MONGO_LDAP[Reconnect]='true'
MONGO_LDAP[Reject_Unauthorized]='true'
MONGO_LDAP[Search_Page_Size]='250'
MONGO_LDAP[Search_Size_Limit]='5000'
# MONGO_LDAP[Sync_Now]='"ldap_sync_now"'
MONGO_LDAP[Sync_User_Avatar]='true'
MONGO_LDAP[Sync_User_Data]='true'
MONGO_LDAP[Sync_User_Data_FieldMap]='"{\"cn\":\"name\", \"mail\":\"email\"}"'
MONGO_LDAP[Sync_User_Data_Groups]='true'
MONGO_LDAP[Sync_User_Data_GroupsMap]='"{\n\t\"it\": \"it\"\n\t,\"admins\": \"admin\"\n}"'
MONGO_LDAP[Sync_User_Data_Groups_AutoChannels]='false'
MONGO_LDAP[Sync_User_Data_Groups_AutoChannelsMap]='"{\n\t\"it\": \"it\", \"everybody\": \"general\"\n}"'
MONGO_LDAP[Sync_User_Data_Groups_AutoChannels_Admin]='"rocket.cat"'
MONGO_LDAP[Sync_User_Data_Groups_AutoRemove]='false'
MONGO_LDAP[Sync_User_Data_Groups_BaseDN]='""'
MONGO_LDAP[Sync_User_Data_Groups_Enforce_AutoChannels]='false'
MONGO_LDAP[Sync_User_Data_Groups_Filter]='"(&(cn=#{groupName})(memberUid=#{username}))"'
# MONGO_LDAP[Test_Connection]='"ldap_test_connection"'
MONGO_LDAP[Timeout]='600'
MONGO_LDAP[Unique_Identifier_Field]='"uid"'
MONGO_LDAP[User_Search_Field]='"uid"'
MONGO_LDAP[User_Search_Filter]='"(objectclass=inetOrgPerson)"'
MONGO_LDAP[User_Search_Scope]='"sub"'
MONGO_LDAP[Username_Field]='"uid"'


declare -A MONGO_SAML
MONGO_SAML[Custom_Default]='true'
MONGO_SAML[Custom_Default_button_color]='"#1d74f5"'
MONGO_SAML[Custom_Default_button_label_color]='"#FFFFFF"'
MONGO_SAML[Custom_Default_button_label_text]='"SAML login"'
MONGO_SAML[Custom_Default_debug]='true'
MONGO_SAML[Custom_Default_entry_point]="\"https://sso.$DOMAINNAME/auth/realms/master/protocol/saml\""
MONGO_SAML[Custom_Default_generate_username]='false'
MONGO_SAML[Custom_Default_idp_slo_redirect_url]="\"https://sso.$DOMAINNAME/auth/realms/master/protocol/saml\""
MONGO_SAML[Custom_Default_issuer]="\"https://$ROCKETCHAT_HOSTNAME.$DOMAINNAME/_saml/metadata/keycloak"\"
MONGO_SAML[Custom_Default_logout_behaviour]='"SAML"'
MONGO_SAML[Custom_Default_mail_overwrite]='false'
MONGO_SAML[Custom_Default_name_overwrite]='false'
MONGO_SAML[Custom_Default_provider]='"keycloak"'
# Probably the IP's key
MONGO_SAML[Custom_Default_cert]=''
MONGO_SAML[Custom_Default_private_key]=''
MONGO_SAML[Custom_Default_public_cert]=''


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


function configure_calendar {
	for item in "${!CALENDAR_CONFIGURATION[@]}"; do
		nextcloud_exec "config:app:set" --value "${CALENDAR_CONFIGURATION[$item]}" dav "$item"
	done
}


function configure_nextcloud {
	apps_enable groupfolders user_ldap user_saml richdocuments mail calendar
	test "$LOCAL_SETUP" = yes || nextcloud_exec "config:system:set" --value "https" "overwriteprotocol"
	for item in "${!MAIL_CONFIGURATION[@]}"; do
		nextcloud_exec "config:system:set" --value "${MAIL_CONFIGURATION[$item]}" app.mail.accounts.default "$item"
	done
}


function configure_nextcloud_ldap {
	if ldap_has_config; then
		c_id=$(ldap_config_id)
	else
		out=$(nextcloud_exec 'ldap:create-empty-config')
		c_id=$(ldap_config_id)
		# c_id=$(sed -e 's/.*configID\s*//' <<< "$out")
	fi

	for item in "${!LDAP_CONFIGURATION[@]}"; do
		nextcloud_exec "ldap:set-config" "$c_id" "$item" "${LDAP_CONFIGURATION[$item]}"
	done
}


function configure_nextcloud_saml_except_certs {
	for item in "${!SAML_CONFIGURATION[@]}"; do
		grep -q 'x509cert' <<< $item && continue
		grep -q 'privateKey' <<< $item && continue
		nextcloud_exec "config:app:set" --value "${SAML_CONFIGURATION[$item]}" user_saml "$item"
	done
}


# $1: Literal Client ID URL
function _keycloak_client_id {
	keycloak_exec config credentials --server http://localhost:8080/auth --realm master --user "$ADMIN_USER" --password "$ADMIN_PASSWORD" &> /dev/null
	printf "%s" "$(keycloak_exec get clients -q "clientId=$1" -F id | jq -M --raw-output '.[0].id')"
}


function configure_keycloak {
	keycloak_exec config credentials --server http://localhost:8080/auth --realm master --user "$ADMIN_USER" --password "$ADMIN_PASSWORD"
	client_id=$(_keycloak_client_id $NEXTCLOUD_HOSTNAME)
	if test "$client_id" = null; then
		echo 'ERRORRE!'
	fi
	# TODO: Create the Nextcloud client by downloading its SAML metadata and supplying it to the API
	# TODO: get the mappings, set mappings and uniqueness and whatever.
}


function configure_saml_certs {
	tmp_dir=$(mktemp -d -t certs-XXXXXX)
	sp_cert="$tmp_dir/myservice.cert"
	sp_key="$tmp_dir/myservice.key"
	openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -batch -keyout "$sp_key" -out "$sp_cert"

	# SP - KEYCLOAK PART
	keycloak_exec config credentials --server http://localhost:8080/auth --realm master --user "$ADMIN_USER" --password "$ADMIN_PASSWORD"
	# SP - NEXTCLOUD PART
	client_id=$(_keycloak_client_id "https://$NEXTCLOUD_HOSTNAME.$DOMAINNAME/apps/user_saml/saml/metadata")
	keycloak_exec update "clients/$client_id" -s 'attributes."saml.signing.certificate"='"$(cat "$sp_cert" | head -n -1 | tail -n +2)"
	nextcloud_exec "config:app:set" --value="$(cat "$sp_cert")" user_saml "sp-x509cert"
	nextcloud_exec "config:app:set" --value="$(cat "$sp_key")" user_saml "sp-privateKey"

	# SP - ROCKET PART
	client_id=$(_keycloak_client_id "https://$ROCKETCHAT_HOSTNAME.$DOMAINNAME/_saml/metadata/keycloak")
	keycloak_exec update "clients/$client_id" -s 'attributes."saml.signing.certificate"='"$(cat "$sp_cert" | head -n -1 | tail -n +2)"
	mongo_rocket_eval_update rocketchat_settings SAML_Custom_Default_public_cert "\"$(escape_newlines "$(cat "$sp_cert")")\""
	mongo_rocket_eval_update rocketchat_settings SAML_Custom_Default_private_key "\"$(escape_newlines "$(cat "$sp_key")")\""

	# SP - TEAP PART
	# Be sure to disable assertions encryption and document signing.
	# Otherwise, the Python SAML client is confused by too many keys.
	# Related: https://github.com/XML-Security/signxml/issues/143
	client_id=$(_keycloak_client_id "https://$TEAP_HOSTNAME.$DOMAINNAME/saml/metadata.xml")
	test -n "$client_id" && keycloak_exec update "clients/$client_id" -s 'attributes."saml.signing.certificate"='"$(cat "$sp_cert" | head -n -1 | tail -n +2)"
	teap_flask saml sp-cert -- "$(cat "$sp_cert")"
	teap_flask saml sp-key -- "$(cat "$sp_key")"

	# cleanup
	rm -f "$sp_cert" "$sp_key"

	# IdP - KEYCLOAK PART
	idp_cert="$tmp_dir/myidp.cert"
	printf '%s\n' '-----BEGIN CERTIFICATE-----' > "$idp_cert"
	# keycloak_realm_cert=$(keycloak_exec get realms/master/keys -F 'keys(publicKey)' | jq -M --raw-output 'flatten|add.publicKey')
	keycloak_realm_cert=$(keycloak_exec get realms/master/keys -F 'keys(certificate)' | jq -M --raw-output 'flatten|add.certificate')
	printf '%s\n' "$keycloak_realm_cert" >> "$idp_cert"
	printf '%s\n' '-----END CERTIFICATE-----' >> "$idp_cert"

	# IdP - NEXTCLOUD PART
	nextcloud_exec "config:app:set" --value="$(cat "$idp_cert")" user_saml "idp-x509cert"

	# IdP - ROCKET PART
	# mongo_rocket_eval_update rocketchat_settings SAML_Custom_Default_cert "\"$keycloak_realm_cert\""
	mongo_rocket_eval_update rocketchat_settings SAML_Custom_Default_cert "\"$(escape_newlines "$keycloak_realm_cert")\""

	# IdP - TEAP PART
	teap_flask saml idp-cert -- "$(cat "$idp_cert")"

	# cleanup
	rm -f "$idp_cert"
	rm -rf "$tmp_dir"
}


function mongo_rocket {
	docker-compose exec mongo-rocket "$@"
}


function mongo_rocket_eval {
	mongo_rocket mongo 'db/rocketchat' --eval "$1"
}


# $1: DB
# $2: id
# $3: value
function mongo_rocket_eval_update {
	mongo_rocket_eval "db.$1.update({\"_id\": \"$2\"}, {\
	       \$currentDate: { \"_updatedAt\": true},\
	       \$set: { \"value\": $3}\
	})"
}


function configure_rocketchat {
	# Init the mongo db
	for i in $(seq 1 30); do
		mongo_rocket_eval "rs.initiate({ _id: 'rs0', members: [ { _id: 0, host: 'localhost:27017' } ]})" && break || echo "Tried $i times. Waiting 5 secs..."
		sleep 5
	done
}


function configure_rocketchat_ldap {
	for item in "${!MONGO_LDAP[@]}"; do
		mongo_rocket_eval_update rocketchat_settings "LDAP_$item" "${MONGO_LDAP[$item]}"
	done
}


function configure_rocketchat_saml_except_certs {
	for item in "${!MONGO_SAML[@]}"; do
		grep -q 'cert' <<< $item && continue
		grep -q 'private_key' <<< $item && continue
		mongo_rocket_eval_update rocketchat_settings "SAML_$item" "${MONGO_SAML[$item]}"
	done
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


function teap_flask {
	docker-compose exec -e FLASK_APP=backend/app.py teap flask "$@"
}


function configure_teap {
	teap_flask db upgrade
	teap_flask bootstrap
}


# configure_nextcloud
# configure_nextcloud_ldap
# configure_nextcloud_saml_except_certs
# configure_keycloak
# configure_saml_certs
# configure_rocketchat
