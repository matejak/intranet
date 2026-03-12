# intranet
The True Enterprisey Intranet Setup

This project contains support scripts that assist in deployment of an intranet setup based on docker compose and podman.
Namely:

- Installation and enablement of Nextcloud apps.
- Nextcloud LDAP and SAML support.
- Rocketchat LDAP and SAML support.
- OpenLDAP setup.
- Keycloak IDP basic setup.
- Bureau admin utility setup.
- Refresh of SAML SP/IDP certificates.
- PHPLDAPAdmin setup


## Project structure

- Root folder:
  - `start.sh`: Starts respective containers.
  - `provision.sh`: Defines Bash functions that set those containers up.
  - `cleanup_data.sh`: Removes those containers and deletes content of their bind mounts.
- `build` folder: Contains data needed for building of some of the container images.
- `data` folder: Contains persistent data used by the respective containers. Actual data are not part of the repository.


## How to use

Create a file `.env` based on `.env.example`, so Docker Compose can populate variables from it.
You may have to define a bunch of DB-app passwords in there.
The admin password can be also changed, but you will have to repeat the change in the `start.sh` file too, as both containers and provisioning scripts need to know it.

Create a file `data/bureau/env` based on `data/bureau/env.example` and assign a string to the variable `SECRET_KEY`.

Typical usage:
```
bash ./cleanup_data.sh
bash ./start.sh
```
