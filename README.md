# intranet
The True Enterprisey Intranet Setup

This project contains support scripts that assist in deploying an intranet setup based on Docker Compose and Podman.
Namely:

- Installation and enablement of Nextcloud apps.
- Nextcloud LDAP and SAML support.
- Rocket.Chat LDAP and SAML support.
- OpenLDAP setup.
- Basic Keycloak IdP setup.
- Bureau admin utility setup.
- Refreshing SAML SP/IdP certificates.
- phpLDAPadmin setup.


## Project structure

- Root folder:
  - `start.sh`: Starts the respective containers.
  - `provision.sh`: Defines Bash functions that set up those containers.
  - `cleanup_data.sh`: Removes the containers and deletes the contents of their bind mounts.
- `build` folder: Contains data needed to build some of the container images.
- `data` folder: Contains persistent data used by the respective containers. The actual data is not part of the repository.


## How to use

Create a file `.env` based on `.env.example`, so Docker Compose can populate variables from it.
You may have to define a bunch of DB app passwords in there.
The admin password can also be changed, but you will have to repeat the change in the `start.sh` file too, as both containers and provisioning scripts need to know it.

Create a file `data/bureau/env` based on `data/bureau/env.example` and assign a string to the variable `SECRET_KEY`.

Typical usage:
```
bash ./cleanup_data.sh
bash ./start.sh
```
