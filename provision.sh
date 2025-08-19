#!/bin/bash

DOMAINNAME="${DOMAINNAME:-entint.org}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
ADMIN_USER='admin'

SSO_HOSTNAME='sso'
NEXTCLOUD_HOSTNAME="${NEXTCLOUD_HOSTNAME:-next}"
ROCKETCHAT_HOSTNAME="${ROCKETCHAT_HOSTNAME:-rocket}"
TEAP_HOSTNAME="${TEAP_HOSTNAME:-teap}"
COLLABORA_HOSTNAME="${COLLABORA_HOSTNAME:-collabora}"
KEYCLOAK_HOSTNAME="${KEYCLOAK_HOSTNAME:-sso}"
BUREAU_HOSTNAME="${BUREAU_HOSTNAME:-bureau}"
MAIL_SUBDOMAIN=mail

MAIL_HOST=$DOMAINNAME
test -n "$MAIL_SUBDOMAIN" && MAIL_HOST="$MAIL_SUBDOMAIN.$MAIL_HOST"

NEXTCLOUD_WANT_MAIL=no
IMAP_HOSTNAME=imap.$MAIL_HOST
SMTP_HOSTNAME=smtp.$MAIL_HOST

LOCAL_SETUP="${LOCAL_SETUP:-no}"
# yes if we are testing things locally, i.e. without a real domain
if test "$DOMAINNAME" = localhost; then
	LOCAL_SETUP=yes
	NEXTCLOUD_ROOT_URI=http://localhost:1181
	ROCKETCHAT_ROOT_URI=http://localhost:1182
	KEYCLOAK_ROOT_URI=http://localhost:1184
	BUREAU_ROOT_URI=http://localhost:1185
	COLLABORA_ROOT_URI=http://localhost:9999
	TEAP_ROOT_URI=http://localhost:9999
else
	NEXTCLOUD_ROOT_URI=https://$NEXTCLOUD_HOSTNAME.$DOMAINNAME
	ROCKETCHAT_ROOT_URI=https://$ROCKETCHAT_HOSTNAME.$DOMAINNAME
	COLLABORA_ROOT_URI=https://$COLLABORA_HOSTNAME.$DOMAINNAME
	KEYCLOAK_ROOT_URI=https://$KEYCLOAK_HOSTNAME.$DOMAINNAME
	BUREAU_ROOT_URI=https://$BUREAU_HOSTNAME.$DOMAINNAME
	TEAP_ROOT_URI=https://$TEAP_HOSTNAME.$DOMAINNAME
fi


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
	docker-compose exec openldap ldapsearch -b "${search_base_restriction}$LDAP_BASE_DN" -x -w "$ADMIN_PASSWORD" -D "$ADMIN_DN" "$filter" "$output_field"
	# docker-compose exec openldap bash -c "ldapsearch -b \"${search_base_restriction}\$LDAP_BASE_DN\" -x -w \"\$LDAP_ADMIN_PASSWORD\" -D \"cn=admin,\$LDAP_BASE_DN\" \"$filter\" \"$output_field\""
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
	docker-compose exec openldap bash -c "ldapsearch -b \"ou=$1,\$LDAP_BASE_DN\" -x -w \"\$LDAP_ADMIN_PASSWORD\" -D \"$ADMIN_DN\" \"(cn=$2)\" \"$3\""
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
ADMIN_DN="cn=$ADMIN_USER,$LDAP_BASE_DN"
READER_DN="uid=reader,ou=special,$LDAP_BASE_DN"
MAINT_DN="uid=maintenance,ou=special,$LDAP_BASE_DN"
ALL_PEOPLE_DN="ou=people,$LDAP_BASE_DN"
ACTIVE_PEOPLE_DN="ou=active,$ALL_PEOPLE_DN"


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
LDAP_CONFIGURATION["ldapAttributesForGroupSearch"]="cn;description"
LDAP_CONFIGURATION["ldapBase"]="$LDAP_BASE_DN"
LDAP_CONFIGURATION["ldapBaseGroups"]="$LDAP_BASE_DN"
LDAP_CONFIGURATION["ldapBaseUsers"]="$ACTIVE_PEOPLE_DN"
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


declare -A LDAP_INDIRECT_CONFIGURATION
LDAP_INDIRECT_CONFIGURATION["ldapAgentPassword"]=LDAP_READER_PASSWORD
LDAP_INDIRECT_CONFIGURATION["ldapAgentName"]=LDAP_READER_DN


declare -A NEXT_SAML_CONFIGURATION
NEXT_SAML_CONFIGURATION["general-uid_mapping"]="username"
NEXT_SAML_CONFIGURATION["idp-entityId"]="$KEYCLOAK_ROOT_URI/realms/master"
NEXT_SAML_CONFIGURATION["idp-singleSignOnService.url"]="$KEYCLOAK_ROOT_URI/realms/master/protocol/saml"
# NEXT_SAML_CONFIGURATION["type"]="saml" ## deprecated
NEXT_SAML_CONFIGURATION["general-idp0_display_name"]="SAMLLogin"
# NEXT_SAML_CONFIGURATION["general-allow_multiple_user_back_ends"]="1"  ## deprecated

# Service Provider certificate and key - That's us, Nextcloud
NEXT_SAML_CONFIGURATION["sp-privateKey"]=""
NEXT_SAML_CONFIGURATION["sp-x509cert"]=""
NEXT_SAML_CONFIGURATION["sp-name-id-format"]=urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress

NEXT_SAML_CONFIGURATION["saml-attribute-mapping-email_mapping"]=""
NEXT_SAML_CONFIGURATION["idp-singleLogoutService.url"]="$KEYCLOAK_ROOT_URI/realms/master/protocol/saml"
NEXT_SAML_CONFIGURATION["security-authnRequestsSigned"]="1"
NEXT_SAML_CONFIGURATION["security-logoutRequestSigned"]="1"
NEXT_SAML_CONFIGURATION["security-logoutResponseSigned"]="1"
NEXT_SAML_CONFIGURATION["security-wantMessagesSigned"]="1"
NEXT_SAML_CONFIGURATION["security-wantAssertionsSigned"]="1"
NEXT_SAML_CONFIGURATION["saml-attribute-mapping-displayName_mapping"]=""

# Identity Provider certificate - That's Keycloak
NEXT_SAML_CONFIGURATION["idp-x509cert"]=""


declare -A OFFICE_CONFIGURATION
OFFICE_CONFIGURATION["wopi_url"]="$COLLABORA_ROOT_URI"
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
MONGO_LDAP[Authentication_UserDN]="\"$ADMIN_DN\""
MONGO_LDAP[Background_Sync]='true'
MONGO_LDAP[Background_Sync_Import_New_Users]='true'
MONGO_LDAP[Background_Sync_Interval]='"Every 2 hours"'
MONGO_LDAP[Background_Sync_Keep_Existant_Users_Updated]='true'
MONGO_LDAP[BaseDN]="\"$ACTIVE_PEOPLE_DN\""
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
MONGO_LDAP[Sync_User_Data_Groups_BaseDN]="\"ou=divisions,$LDAP_BASE_DN\""
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
MONGO_SAML[Custom_Default_entry_point]="\"$KEYCLOAK_ROOT_URI/realms/master/protocol/saml\""
MONGO_SAML[Custom_Default_generate_username]='false'
MONGO_SAML[Custom_Default_idp_slo_redirect_url]="\"$KEYCLOAK_ROOT_URI/realms/master/protocol/saml\""
MONGO_SAML[Custom_Default_issuer]="\"$ROCKETCHAT_ROOT_URI/_saml/metadata/keycloak"\"
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
	docker-compose exec --user www-data "$NEXTCLOUD_HOSTNAME" "$@"
}


function nextcloud_exec_occ {
	nextcloud_exec php occ --no-ansi "$@"
}


# $1: LDAP Config ID
# $2: Configuration key
# $3: Variable holding value
function nextcloud_exec_occ_set_ldap_indirect {
	nextcloud_exec "bash" -c "php occ --no-ansi ldap:set-config \"$1\" \"$2\" \"\$$3\""
}


function keycloak_exec {
	docker-compose exec keycloak '/opt/keycloak/bin/kcadm.sh' "$@"
}


function apps_enable {
	for app in "$@"; do
		nextcloud_exec_occ "app:install" "$app"
		nextcloud_exec_occ "app:enable" "$app"
	done
}


function ldap_has_config {
	out=$(nextcloud_exec_occ ldap:show-config)
	test -n "$out" && return 0 || return 1
}


function ldap_config_id {
	out=$(nextcloud_exec_occ ldap:show-config)
	printf "%s" "$(grep '\<Configuration\>' <<< "${out}" | cut -f 3 -d '|' | tr -d '[:blank:]')"
}


function configure_office {
	for item in "${!OFFICE_CONFIGURATION[@]}"; do
		nextcloud_exec_occ "config:app:set" --value "${OFFICE_CONFIGURATION[$item]}" richdocuments "$item"
	done
}


function configure_calendar {
	for item in "${!CALENDAR_CONFIGURATION[@]}"; do
		nextcloud_exec_occ "config:app:set" --value "${CALENDAR_CONFIGURATION[$item]}" dav "$item"
	done
}


function configure_nextcloud {
	apps_enable groupfolders user_ldap user_saml richdocuments calendar deck
	if test "$LOCAL_SETUP" = yes; then
		nextcloud_exec_occ config:system:set --type string --value "localhost" -- trusted_domains 0
		nextcloud_exec_occ config:system:set --type string --value "gateway" -- trusted_domains 1
	else
		nextcloud_exec_occ config:system:set --type string --value "$NEXTCLOUD_HOSTNAME" -- trusted_domains 2
		nextcloud_exec_occ "config:system:set" --value "https" "overwriteprotocol"
	fi
	if test "$NEXTCLOUD_WANT_MAIL" = yes; then
		apps_enable mail
		for item in "${!MAIL_DEFAULTS[@]}"; do
			nextcloud_exec_occ "config:system:set" --value "${MAIL_DEFAULTS[$item]}" app.mail.accounts.default "$item"
		done
		for item in "${!MAIL_INT_CONFIGURATION[@]}"; do
			nextcloud_exec_occ "config:system:set" app.mail --value "${MAIL_INT_CONFIGURATION[$item]}" --type int "$item"
		done
	fi
}


function configure_nextcloud_ldap {
	if ldap_has_config; then
		c_id=$(ldap_config_id)
	else
		out=$(nextcloud_exec_occ 'ldap:create-empty-config')
		c_id=$(ldap_config_id)
		# c_id=$(sed -e 's/.*configID\s*//' <<< "$out")
	fi
	for item in "${!LDAP_INDIRECT_CONFIGURATION[@]}"; do
		nextcloud_exec_occ_set_ldap_indirect "$c_id" "$item" "${LDAP_INDIRECT_CONFIGURATION[$item]}"
	done

	for item in "${!LDAP_CONFIGURATION[@]}"; do
		nextcloud_exec_occ "ldap:set-config" "$c_id" "$item" "${LDAP_CONFIGURATION[$item]}"
	done
}


function configure_nextcloud_saml_except_certs {
	DEFAULT_SAML_PROVIDER=1
	for item in "${!NEXT_SAML_CONFIGURATION[@]}"; do
		grep -q 'x509cert' <<< $item && continue
		grep -q 'privateKey' <<< $item && continue
		nextcloud_exec_occ "saml:config:set" "--$item" "${NEXT_SAML_CONFIGURATION[$item]}" $DEFAULT_SAML_PROVIDER
	done
}


function configure_nextcloud_saml_certs {
	DEFAULT_SAML_PROVIDER=1
	_keycloak_login
	inline_idp_cert="$(get_idp_cert)"
	nextcloud_exec_occ "saml:config:set" "--idp-x509cert=$inline_idp_cert" -- $DEFAULT_SAML_PROVIDER

	certdir="$(generate_rsa_certs next)"
	inline_sp_cert="$(cat "$certdir/service.cert")"
	inline_sp_key="$(cat "$certdir/service.key")"
	rm -rf "$certdir"
	internal_client_id=$(_keycloak_client_id "$NEXTCLOUD_ROOT_URI/apps/user_saml/saml/metadata")
	keycloak_update_client "$internal_client_id" 'attributes."saml.signing.certificate"='"$(head -n -1 <<< "$inline_sp_cert" | tail -n +2)"
	nextcloud_exec_occ "saml:config:set" "--sp-x509cert=$inline_sp_cert" $DEFAULT_SAML_PROVIDER
	nextcloud_exec_occ "saml:config:set" "--sp-privateKey=$inline_sp_key" $DEFAULT_SAML_PROVIDER
}


function _keycloak_login {
	keycloak_exec config credentials --server http://localhost:8080 --realm master --user "$ADMIN_USER" --password "$ADMIN_PASSWORD" &> /dev/null
}


# $1: The client ID
# Rest: Update Arguments without -s
function keycloak_update_client {
	local _client_id="$1"
	local _args=()
	shift
	for arg in "$@"; do
		_args+=(-s "$arg")
	done
	keycloak_exec update "clients/$_client_id" --realm master "${_args[@]}"
}


# $1: Literal Client ID URL
function _keycloak_client_id {
	printf "%s" "$(keycloak_exec get clients --realm master --server http://localhost:8080 -q "clientId=$1" -F id | jq -M --raw-output '.[0].id')"
}


function configure_keycloak_rocketchat {
	_keycloak_login
	client_id="$ROCKETCHAT_ROOT_URI/_saml/metadata/keycloak"
	internal_client_id=$(_keycloak_client_id "$client_id")
	if test "$internal_client_id" = null; then
		keycloak_exec create clients -r master -s "clientId=$client_id" -s protocol=saml -s enabled=true
		internal_client_id=$(_keycloak_client_id "$client_id")
	fi
	# Get list of existing config:
	# keycloak_exec get "clients/$internal_client_id" --realm master
	keycloak_update_client "$internal_client_id" "name=Rocket.chat" "redirectUris=[\"$ROCKETCHAT_ROOT_URI/_saml/validate/keycloak\"]"
}


function configure_keycloak_next {
	_keycloak_login
	client_id="$NEXTCLOUD_ROOT_URI/apps/user_saml/saml/metadata"
	internal_client_id=$(_keycloak_client_id "$client_id")
	if test "$internal_client_id" = null; then
		keycloak_exec create clients -r master -s "clientId=$client_id" -s protocol=saml -s enabled=true
		internal_client_id=$(_keycloak_client_id "$client_id")
	fi
	# Get list of existing config:
	# keycloak_exec get "clients/$internal_client_id" --realm master
	keycloak_update_client "$internal_client_id" "name=Nextcloud" "redirectUris=[\"$NEXTCLOUD_ROOT_URI/apps/user_saml/saml/acs\"]"
}


function configure_keycloak_bureau {
	_keycloak_login
	client_id="$BUREAU_ROOT_URI/login/saml/metadata"
	internal_client_id=$(_keycloak_client_id "$client_id")
	if test "$internal_client_id" = null; then
		keycloak_exec create clients -r master -s "clientId=$client_id" -s protocol=saml -s enabled=true
		internal_client_id=$(_keycloak_client_id "$client_id")
	fi
	# Get list of existing config:
	# keycloak_exec get "clients/$internal_client_id" --realm master
	keycloak_update_client "$internal_client_id" "name=Bureau" "redirectUris=[\"$BUREAU_ROOT_URI/login/saml/acs\"]"
}


function _configure_teap_saml_certs {
	tmp_dir=$(mktemp -d -t certs-XXXXXX)
	sp_cert="$tmp_dir/myservice.cert"
	sp_key="$tmp_dir/myservice.key"
	openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -batch -keyout "$sp_key" -out "$sp_cert"

	echo Authorize to KC
	# SP - KEYCLOAK PART
	_keycloak_login

	# SP - TEAP PART
	# Be sure to disable assertions encryption and document signing.
	# Otherwise, the Python SAML client is confused by too many keys.
	# Related: https://github.com/XML-Security/signxml/issues/143
	echo get TEAP Client ID KC
	client_id=$(_keycloak_client_id "$TEAP_ROOT_URI/saml/metadata.xml")
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


function get_idp_cert {
	keycloak_realm_cert=$(keycloak_exec get realms/master/keys -F 'keys(certificate)' | jq -M --raw-output 'flatten|add.certificate')
	inline_idp_cert="-----BEGIN CERTIFICATE-----\n${keycloak_realm_cert}\n-----END CERTIFICATE-----\n"
	printf -- "$inline_idp_cert"
}


# $1 prefix
function generate_rsa_certs {
	tmp_dir=$(mktemp -d -t certs-$1-XXXXXX)
	sp_cert="$tmp_dir/service.cert"
	sp_key="$tmp_dir/service.key"
	openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -batch -keyout "$sp_key" -out "$sp_cert"
	printf '%s' "$tmp_dir"
}


function configure_saml_certs {
	tmp_dir=$(mktemp -d -t certs-XXXXXX)
	sp_cert="$tmp_dir/myservice.cert"
	sp_key="$tmp_dir/myservice.key"
	openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 -batch -keyout "$sp_key" -out "$sp_cert"

	# SP - KEYCLOAK PART
	_keycloak_login
	# SP - NEXTCLOUD PART
	DEFAULT_SAML_PROVIDER=1
	client_id=$(_keycloak_client_id "$NEXTCLOUD_ROOT_URI/apps/user_saml/saml/metadata")
	keycloak_exec update "clients/$client_id" -s 'attributes."saml.signing.certificate"='"$(cat "$sp_cert" | head -n -1 | tail -n +2)"
	nextcloud_exec_occ "saml:config:set" "--sp-x509cert" "$(cat "$sp_cert")" $DEFAULT_SAML_PROVIDER
	nextcloud_exec_occ "saml:config:set" "--sp-privateKey" "$(cat "$sp_key")" $DEFAULT_SAML_PROVIDER

	# SP - ROCKET PART
	client_id=$(_keycloak_client_id "$ROCKETCHAT_ROOT_URI/_saml/metadata/keycloak")
	keycloak_exec update "clients/$client_id" -s 'attributes."saml.signing.certificate"='"$(cat "$sp_cert" | head -n -1 | tail -n +2)"
	mongo_rocket_eval_update rocketchat_settings SAML_Custom_Default_public_cert "\"$(escape_newlines "$(cat "$sp_cert")")\""
	mongo_rocket_eval_update rocketchat_settings SAML_Custom_Default_private_key "\"$(escape_newlines "$(cat "$sp_key")")\""

	# SP - TEAP PART
	# Be sure to disable assertions encryption and document signing.
	# Otherwise, the Python SAML client is confused by too many keys.
	# Related: https://github.com/XML-Security/signxml/issues/143
	client_id=$(_keycloak_client_id "$TEAP_ROOT_URI/saml/metadata.xml")
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
	nextcloud_exec_occ "saml:config:set" "--idp-x509cert" "$(cat "$idp_cert")" $DEFAULT_SAML_PROVIDER

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
	mongo_rocket mongosh 'db/rocketchat' --eval "$1"
}


# $1: DB
# $2: id
# $3: value
function mongo_rocket_eval_update {
	mongo_rocket_eval "db.$1.updateOne({\"_id\": \"$2\"}, {\
	       \$currentDate: { \"_updatedAt\": true},\
	       \$set: { \"value\": $3}\
	})"
}


function configure_rocketchat {
	# Init the mongo db
	for i in $(seq 1 30); do
		mongo_rocket_eval "rs.status()" > /dev/null && return
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


function configure_rocketchat_saml_certs {
	DEFAULT_SAML_PROVIDER=1
	_keycloak_login
	inline_idp_cert="$(get_idp_cert)"
	mongo_rocket_eval_update rocketchat_settings "SAML_Custom_Default_cert" "\"$(escape_newlines "$inline_sp_cert")\""

	certdir="$(generate_rsa_certs rocket)"
	inline_sp_cert="$(cat "$certdir/service.cert")"
	inline_sp_key="$(cat "$certdir/service.key")"
	rm -rf "$certdir"
	mongo_rocket_eval_update rocketchat_settings "SAML_Custom_Default_public_cert" "\"$(escape_newlines "$inline_sp_cert")\""
	mongo_rocket_eval_update rocketchat_settings "SAML_Custom_Default_private_key" "\"$(escape_newlines "$inline_sp_key")\""
	internal_client_id=$(_keycloak_client_id "$ROCKETCHAT_ROOT_URI/_saml/metadata/keycloak")
	keycloak_update_client "$internal_client_id" 'attributes."saml.signing.certificate"='"$(head -n -1 <<< "$inline_sp_cert" | tail -n +2)"
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


# $1: Ldif as string
function ldap_modify {
	docker-compose exec -T openldap ldapmodify -Q -Y EXTERNAL -H ldapi:///
}


function configure_ldap_acl {
ldap_modify << EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: to attrs=cn,userPassword,givenName,sn,jpegPhoto
  by self write
  by dn="$ADMIN_DN" write
  by * none break
olcAccess: to dn.subtree="$ALL_PEOPLE_DN"
  by dn="$MAINT_DN" read
  by dn="$ADMIN_DN" write
  by * none break
olcAccess: to dn.subtree="$ACTIVE_PEOPLE_DN"
  by dn="$READER_DN" read
  by dn.one="$ACTIVE_PEOPLE_DN" read
olcAccess: to dn="$READER_DN"
  by anonymous auth
olcAccess: to dn="$MAINT_DN"
  by anonymous auth
olcAccess: to *
  by self read
  by dn="$ADMIN_DN" write
  by dn="$READER_DN" read
  by dn="$MAINT_DN" read
  by * none
EOF
}


# $1: filename
# $2: edit-expression
function _edit_json {
	local _tmpfile=/tmp/json-edit
	jq "$2" "$1" > $_tmpfile && mv $_tmpfile "$1"
	rm -f $_tmpfile
}


function configure_bureau_saml_except_certs {
	DATADIR=data
cat > "$DATADIR/bureau/settings.json" << EOF
{
    "strict": true,
    "debug": false,
    "sp": {
        "entityId": "$BUREAU_ROOT_URI/login/saml/metadata",
        "assertionConsumerService": {
            "url": "$BUREAU_ROOT_URI/login/saml/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": "$BUREAU_ROOT_URI/login/saml/sls",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "x509cert": "",
        "privateKey": ""
    },
    "idp": {
        "entityId": "$KEYCLOAK_ROOT_URI/realms/master",
        "singleSignOnService": {
            "url": "$KEYCLOAK_ROOT_URI/realms/master/protocol/saml",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": "$KEYCLOAK_ROOT_URI/realms/master/protocol/saml",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": ""
    },
    "security": {
        "nameIdEncrypted": false,
        "authnRequestsSigned": true,
        "logoutRequestSigned": true,
        "logoutResponseSigned": true,
        "signMetadata": false,
        "wantMessagesSigned": true,
        "wantAssertionsSigned": true,
        "wantNameId" : true,
        "wantNameIdEncrypted": false,
        "wantAssertionsEncrypted": false,
        "allowSingleLabelDomains": false,
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        "rejectDeprecatedAlgorithm": true
    }
}
EOF
}


function configure_bureau_saml_certs {
	DATADIR=data
	local _bureau_config="$DATADIR/bureau/settings.json"

	_keycloak_login
	pure_inline_idp_cert="$(get_idp_cert | head -n -1 | tail -n +2)"
	_edit_json "$_bureau_config" ".idp.x509cert = \"$pure_inline_idp_cert\""

	certdir="$(generate_rsa_certs bureau)"
	pure_inline_sp_cert="$(head -n -1 "$certdir/service.cert" | tail -n +2)"
	pure_inline_sp_key="$(head -n -1 "$certdir/service.key" | tail -n +2)"
	rm -rf "$certdir"
	internal_client_id=$(_keycloak_client_id "$BUREAU_ROOT_URI/login/saml/metadata")
	keycloak_update_client "$internal_client_id" 'attributes."saml.signing.certificate"='"$pure_inline_sp_cert"
	_edit_json "$_bureau_config" ".sp.x509cert = \"$pure_inline_sp_cert\""
	_edit_json "$_bureau_config" ".sp.privateKey = \"$pure_inline_sp_key\""
}


# configure_nextcloud
# configure_nextcloud_ldap
# configure_nextcloud_saml_except_certs
# configure_keycloak
# configure_saml_certs
# configure_rocketchat
