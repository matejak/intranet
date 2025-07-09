# intranet
The True Enterprisey Intranet Setup

This project contains support scripts that assist in deployment of an intranet setup based on docker-compose.
Namely:

- Installation and enablement of Nextcloud apps.
- Nextcloud LDAP and SAML support.
- Rocketchat LDAP and SAML support.
- OpenLDAP setup.
- Keycloak IDP basic setup.
- TEAP admin utility setup.
- Refresh of SAML SP/IDP certificates.
- Proxy gateway setup.


## Project structure

- Root folder:
  - `launch.sh`: Start respective containers.
  - `provision.sh`: Define Bash functions that set those containers up.
  - `teardown.sh`: Discard those containers.
- `build` folder: Contains data needed for building of some of the container images.
- `data` folder: Contains persistent data used by the respective containers. Actual data are not part of the repository.
- `config` folder: Contains config files (or templates of thereof) exposed to containers.


## Howto on Fedora

#. Create a folder for shared nginx config files:
```
groupadd shared_nginx
mkdir /srv/shared_nginx_d
chmod g+w shared_nginx_d
chown runner:shared_nginx shared_nginx_d
gpasswd -a ... shared_nginx

Configure Cockpit to behave behind a reverse proxy (don't forget about Origins config key)

```
