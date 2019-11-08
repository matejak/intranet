hostnames="
        collabora
        ldap
        next
        rocket
        sso
        teap
"

args=(-d entint.org)
for n in $hostnames; do
        args+=(-d $n.entint.org)
done

certbot certonly "${args[@]}"
