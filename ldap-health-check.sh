#!/bin/bash
. provision.sh
ldapwhoami -H ldap://localhost:389 -D "$ADMIN_DN" -w "$ADMIN_PASSWORD"
