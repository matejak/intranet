#!/bin/bash

DOMAINNAME="${DOMAINNAME:-entint.org}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
ADMIN_PASSWORD=enterprisey
ADMIN_USER='admin'

SSO_HOSTNAME='sso'
NEXTCLOUD_HOSTNAME="${NEXTCLOUD_HOSTNAME:-next}"
ROCKETCHAT_HOSTNAME="${ROCKETCHAT_HOSTNAME:-rocket}"
TEAP_HOSTNAME="${TEAP_HOSTNAME:-teap}"
COLLABORA_HOSTNAME="${COLLABORA_HOSTNAME:-collabora}"
MAIL_SUBDOMAIN=mail

MAIL_HOST=$DOMAINNAME
test -n "$MAIL_SUBDOMAIN" && MAIL_HOST="$MAIL_SUBDOMAIN.$MAIL_HOST"

IMAP_HOSTNAME=imap.$MAIL_HOST
SMTP_HOSTNAME=smtp.$MAIL_HOST

# yes if we are testing things locally, i.e. without a real domain
LOCAL_SETUP="${LOCAL_SETUP:-yes}"


# $1: db host stem
function db_admin {
	docker-compose exec "db-$1" bash -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
}


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


# $1: filter
# $2: output field
# $3: search base restriction (optional, without the comma if specified)
# We use bash statement to let the container do the env var substitution
function ldap_query {
	local search_base_restriction output_field filter
	filter="$1"
	output_field="$2"
	test -n "$3" && search_base_restriction="$3,"
	docker-compose exec openldap bash -c "ldapsearch -b \"${search_base_restriction}\$LDAP_BASE_DN\" -x -w \"\$LDAP_ADMIN_PASSWORD\" -D \"cn=admin,\$LDAP_BASE_DN\" \"$filter\" \"$output_field\""
}


# $1: filter
# $2: output field
# $3: output array name
# $4: search base restriction (optional, without the comma if specified)
function ldap_extract {
	readarray -t "$3" < <(ldap_query "$1" "$2" "$4" | grep "^$2" | cut -f 1 -d ' ' --complement)
}


# $1: ou name
# $2: cn of groups under that ou
# $3: what to query
# We use bash statement to let the container do the env var substitution
function ldap_query_ou {
	docker-compose exec openldap bash -c "ldapsearch -b \"ou=$1,\$LDAP_BASE_DN\" -x -w \"\$LDAP_ADMIN_PASSWORD\" -D \"cn=admin,\$LDAP_BASE_DN\" \"(cn=$2)\" \"$3\""
}


# $1: before
# $2: after
function change_mail_domain {
	ldap_extract "(mail=*@$1)" dn dns
	ldap_extract "(mail=*@$1)" mail mails
	for idx in "${!dns[@]}"; do
		change_mail_of_dn "${dns[$idx]}" "$(cut -f 1 -d @ <<< "${mails[$idx]}")" "$2"
	done
}


# $1: email address
# $2: old in days, default 90
function search_for_old_trashed_mails {
	local old=${2:-90}
	docker-compose exec mail doveadm search -u "$1"  mailbox Trash savedbefore "${old}d"
}


# $1: email address
# $2: old in days, default 90
function delete_old_trashed_mails {
	local old=${2:-90}
	docker-compose exec mail doveadm expunge -u "$1" mailbox Trash savedbefore "${old}d"
}


# $1: Arguments to doveadm as one single string
function doveadm_exec {
	docker-compose exec mail bash -c "doveadm $1"
}


# $1: Shared from
# $2: Shared to
# $3: permissions as string
function doveadm_acl_add {
	doveadm_exec "acl add -u \"$1@\$DOMAIN\" 'Inbox' \"user=$2@\$DOMAIN\" $3"
}


# $1: Shared from
# $2: Shared to
# $3: permissions as string
function doveadm_acl_add_all {
	doveadm_acl_add "$1" "$2" "lookup read write write-seen write-deleted insert post expunge"
}


function dovecot_share_all_inboxes {
	dovecot_share_inboxes ddea
	dovecot_share_inboxes cdea
	dovecot_share_inboxes special
}


function strip_string {
	grep -oP '^[\w\._-]*' <<< "$1"
}


# $1: ou name - e.g. ddea
function dovecot_share_inboxes {
	cns=()
	ldap_extract '(&(mailEnabled=TRUE)(objectClass=*))' cn cns "ou=$1"
	for cn in "${cns[@]}"; do
		dovecot_share_inbox "$1" "$(strip_string "$cn")"
	done
}


# $1: ou name - e.g. ddea
# $2: cn of groups under that ou - e.g. it
function dovecot_share_inbox {
	echo "$1 $2"
	readarray -t members < <(ldap_query_ou "$1" "$2" "memberUid" | grep "^memberUid" | cut -f 2 -d ' ')
	mail=$(ldap_query_ou "$1" "$2" "mail" | grep "^mail" | cut -f 2 -d ' ')
	group_username=$(cut -f 1 -d @ <<< "$mail")
	for member in "${members[@]}"; do
		echo "Sharing box of $group_username to $member"
		doveadm_acl_add "$group_username" "$(strip_string "$member")" "lookup read write write-seen write-deleted insert post expunge"
	done
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


declare -A FS_OWNERSHIP

FS_OWNERSHIP["mail,/var/mail"]=docker:docker
FS_OWNERSHIP["next,/var/www"]=www-data:www-data
FS_OWNERSHIP["db-next,/var/lib/postgresql/data"]=postgres:postgres
FS_OWNERSHIP["db-nocodb,/var/lib/postgresql/data"]=postgres:postgres
FS_OWNERSHIP["gateway,/etc/nginx/conf.d"]=www-data:www-data
FS_OWNERSHIP["mongo-rocket,/data/db"]=mongodb:root
FS_OWNERSHIP["openldap,/var/lib/ldap"]=openldap:openldap
FS_OWNERSHIP["jampy-newsletter,/jampy"]=root:root
FS_OWNERSHIP["db-jampy-newsletter,/var/lib/postgresql/data"]=postgres:postgres
FS_OWNERSHIP["keycloak,/opt/jboss/keycloak/themes"]=root:root
FS_OWNERSHIP["db-keycloak,/var/lib/postgresql/data"]=postgres:postgres
FS_OWNERSHIP["roundcube,/var/www/html/plugins"]=root:root
FS_OWNERSHIP["roundcube,/var/roundcube/config"]=root:root
FS_OWNERSHIP["db-roundcube,/var/lib/postgresql/data"]=postgres:postgres
FS_OWNERSHIP["wikijs,/data"]=node:node
FS_OWNERSHIP["db-wikijs,/var/lib/postgresql/data"]=postgres:postgres

function settle_fs_ownership {
	for pair in "${!FS_OWNERSHIP[@]}"; do
		name=$(cut -f 1 -d , <<< $pair)
		dir=$(cut -f 2 -d , <<< $pair)
		docker-compose exec -u root $name chown -R ${FS_OWNERSHIP[$pair]} $dir
	done
}

declare -A LDAP_CONFIGURATION
LDAP_CONFIGURATION["lastJpegPhotoLookup"]="0"
LDAP_CONFIGURATION["ldapAgentName"]="uid=reader,ou=special,$LDAP_BASE_DN"
LDAP_CONFIGURATION["ldapAgentPassword"]="kintaro,beru"
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


declare -A MAIL_DEFAULTS
MAIL_DEFAULTS["email"]="%USERID%@$MAIL_HOST"
MAIL_DEFAULTS["imapHost"]="$IMAP_HOSTNAME"
MAIL_DEFAULTS["imapPort"]=143
MAIL_DEFAULTS["imapSslMode"]="tls"
MAIL_DEFAULTS["imapUser"]="%USERID%@$DOMAINNAME"
MAIL_DEFAULTS["smtpHost"]="$SMTP_HOSTNAME"
MAIL_DEFAULTS["smtpPort"]=587
MAIL_DEFAULTS["smtpSslMode"]="tls"
MAIL_DEFAULTS["smtpUser"]="%USERID%@$DOMAINNAME"


declare -A MAIL_INT_CONFIGURATION
MAIL_INT_CONFIGURATION["imap.timeout"]=20
MAIL_INT_CONFIGURATION["smtp.timeout"]=6
MAIL_INT_CONFIGURATION["verify-tls-peer"]=0


declare -A DIVISIONS
DIVISIONS['edu']='Education'
DIVISIONS['fin']='Finance'
DIVISIONS['hra']='HR-and-Admin'
DIVISIONS['it']='IT'
DIVISIONS['leg']='Legal'
DIVISIONS['lgc']='Legacy'
DIVISIONS['lng']='Language'
DIVISIONS['mar']='Marketing'
DIVISIONS['pub']='Publishing'
DIVISIONS['res']='Research'

DIVISIONS_CHANNEL_MAP=""
for code in "${!DIVISIONS[@]}"; do
	value="${DIVISIONS[$code]}"
	DIVISIONS_CHANNEL_MAP="${DIVISIONS_CHANNEL_MAP}\\t\\\"${code}\\\": \\\"Division-${value}\\\",\\n"
done


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
MONGO_LDAP[Sync_User_Data_Groups_AutoChannels]='true'
MONGO_LDAP[Sync_User_Data_Groups_AutoChannelsMap]="\"{\\n${DIVISIONS_CHANNEL_MAP}\\t\\\"everybody\\\": \\\"general\\\"\\n}\""
MONGO_LDAP[Sync_User_Data_Groups_AutoChannels_Admin]='"rocket.cat"'
MONGO_LDAP[Sync_User_Data_Groups_AutoRemove]='false'
MONGO_LDAP[Sync_User_Data_Groups_BaseDN]='"ou=divisions,dc=cspii,dc=org"'
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

# TODO: MONGO_ACCOUNTS
# Don't allow changes of whatever to accounts
# Don't allow registrations

function nextcloud_exec {
	docker-compose exec --user www-data "$NEXTCLOUD_HOSTNAME" php occ --no-ansi "$@"
}


function keycloak_exec {
	docker-compose exec keycloak '/opt/keycloak/bin/kcadm.sh' "$@"
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
	apps_enable groupfolders user_ldap user_saml richdocuments mail calendar deck
	test "$LOCAL_SETUP" = yes || nextcloud_exec "config:system:set" --value "https" "overwriteprotocol"
	for item in "${!MAIL_DEFAULTS[@]}"; do
		nextcloud_exec "config:system:set" --value "${MAIL_DEFAULTS[$item]}" app.mail.accounts.default "$item"
	done
	for item in "${!MAIL_INT_CONFIGURATION[@]}"; do
		nextcloud_exec "config:system:set" app.mail --value "${MAIL_INT_CONFIGURATION[$item]}" --type int "$item"
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
	DEFAULT_SAML_PROVIDER=1
	for item in "${!SAML_CONFIGURATION[@]}"; do
		grep -q 'x509cert' <<< $item && continue
		grep -q 'privateKey' <<< $item && continue
		nextcloud_exec "saml:config:set" "--$item" "${SAML_CONFIGURATION[$item]}" $DEFAULT_SAML_PROVIDER
	done
}


# $1: Literal Client ID URL
function _keycloak_client_id {
	keycloak_exec config credentials --server http://localhost:8080 --realm master --user "$ADMIN_USER" --password "$ADMIN_PASSWORD" &> /dev/null
	printf "%s" "$(keycloak_exec get clients -q "clientId=$1" -F id | jq -M --raw-output '.[0].id')"
}


function configure_keycloak {
	keycloak_exec config credentials --server http://localhost:8080 --realm master --user "$ADMIN_USER" --password "$ADMIN_PASSWORD"
	client_id=$(_keycloak_client_id $NEXTCLOUD_HOSTNAME)
	if test "$client_id" = null; then
		echo 'ERRORRE!'
	fi
	# TODO: Create the Nextcloud client by downloading its SAML metadata and supplying it to the API
	# TODO: get the mappings, set mappings and uniqueness and whatever.
}


function _configure_teap_saml_certs {
	tmp_dir=$(mktemp -d -t certs-XXXXXX)
	sp_cert="$tmp_dir/myservice.cert"
	sp_key="$tmp_dir/myservice.key"
	openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -batch -keyout "$sp_key" -out "$sp_cert"

	echo Authorize to KC
	# SP - KEYCLOAK PART
	keycloak_exec config credentials --server http://localhost:8080 --realm master --user "$ADMIN_USER" --password "$ADMIN_PASSWORD"

	# SP - TEAP PART
	# Be sure to disable assertions encryption and document signing.
	# Otherwise, the Python SAML client is confused by too many keys.
	# Related: https://github.com/XML-Security/signxml/issues/143
	echo get TEAP Client ID KC
	client_id=$(_keycloak_client_id "https://$TEAP_HOSTNAME.$DOMAINNAME/saml/metadata.xml")
	echo ID: $client_id
	echo update KC cert
	test -n "$client_id" && keycloak_exec update "clients/$client_id" -s 'attributes."saml.signing.certificate"='"$(cat "$sp_cert" | head -n -1 | tail -n +2)"
	echo update teap sp cert
	teap_flask saml sp-cert -- "$(cat "$sp_cert")"
	echo update teap sp key
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

	# IdP - TEAP PART
	teap_flask saml idp-cert -- "$(cat "$idp_cert")"

	# cleanup
	rm -f "$idp_cert"
	rm -rf "$tmp_dir"
}

function configure_saml_certs {
	tmp_dir=$(mktemp -d -t certs-XXXXXX)
	sp_cert="$tmp_dir/myservice.cert"
	sp_key="$tmp_dir/myservice.key"
	openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -batch -keyout "$sp_key" -out "$sp_cert"

	# SP - KEYCLOAK PART
	keycloak_exec config credentials --server http://localhost:8080 --realm master --user "$ADMIN_USER" --password "$ADMIN_PASSWORD"
	# SP - NEXTCLOUD PART
	DEFAULT_SAML_PROVIDER=1
	client_id=$(_keycloak_client_id "https://$NEXTCLOUD_HOSTNAME.$DOMAINNAME/apps/user_saml/saml/metadata")
	keycloak_exec update "clients/$client_id" -s 'attributes."saml.signing.certificate"='"$(cat "$sp_cert" | head -n -1 | tail -n +2)"
	nextcloud_exec "saml:config:set" "--sp-x509cert" "$(cat "$sp_cert")" $DEFAULT_SAML_PROVIDER
	nextcloud_exec "saml:config:set" "--sp-privateKey" "$(cat "$sp_key")" $DEFAULT_SAML_PROVIDER

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
	nextcloud_exec "saml:config:set" "--idp-x509cert" "$(cat "$idp_cert")" $DEFAULT_SAML_PROVIDER

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
	docker-compose exec mongo-"$ROCKETCHAT_HOSTNAME" "$@"
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


function create_nginx_files {
	cp config/nginx.conf.in config/nginx.conf
	substitute_env_vars_in_file "config/nginx.conf"
	cp 'data/gateway/config-v1.1.xml.in' 'data/gateway/config-v1.1.xml'
	substitute_env_vars_in_file 'data/gateway/config-v1.1.xml'
}


function teap_flask {
	docker-compose exec -e FLASK_APP=backend/app.py teap flask "$@"
}


function configure_teap {
	teap_flask db upgrade
	teap_flask bootstrap
}



# $1: DB container name
# $2: backup dir
function backup_postgres_db {
	local name backupdir
	name=$1
	backupdir=$2
	# POSTGRES_USER is known only *inside* of the container
	# docker-compose exec $name bash -c 'pg_dumpall -c -U $POSTGRES_USER' > $backupdir/dump_${name}_`date +%Y-%m-%d"_"%H_%M_%S`.sql
	docker-compose exec $name bash -c 'pg_dumpall -c -U $POSTGRES_USER' > $backupdir/dump_${name}.sql
}


# $1: DB container name
# $2: backup dir
function backup_mongo_db {
	local name backupdir
	name=$1
	backupdir=$2
	docker-compose exec $name mongodump --archive > $backupdir/dump_${name}.archive
}


function prune_mongo_db {
	true
	# Do something like:
	# db.rocketchat_sessions.deleteMany({ _updatedAt: { $lt: new ISODate("2024-01-01T00:00:00Z") } })
	# db.rocketchat_statistics.deleteMany({ _updatedAt: { $lt: new ISODate("2024-01-01T00:00:00Z") } })
}


# configure_nextcloud
# configure_nextcloud_ldap
# configure_nextcloud_saml_except_certs
# configure_keycloak
# configure_saml_certs
# configure_rocketchat
