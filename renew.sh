DOMAIN=$1

hostnames="
        collabora
        ldap
        next
        rocket
        sso
        teap
"

args=(-d "$DOMAIN")
for n in $hostnames; do
        args+=(-d "$n.$DOMAIN")
done

certbot certonly "${args[@]}"
