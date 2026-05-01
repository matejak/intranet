# intranet
The True Enterprisey Intranet Setup


This project contains support scripts that assist in deploying an intranet setup based on Docker Compose or Podman.
Namely:

- Installation and enablement of Nextcloud apps.
- Nextcloud LDAP and SAML support.
- Rocket.Chat LDAP and SAML support.
- Redmine SAML support.
- OpenLDAP init, setup of groups.
- Basic Keycloak IdP setup.
- Bureau admin utility setup.
- Refreshing SAML SP/IdP certificates.
- phpLDAPadmin setup.


## Project structure

- Root folder:
  - `start.sh`: Starts the respective containers.
  - `provision.sh`: Defines Bash functions that set up and possibly maintain those containers.
  - `cleanup_data.sh`: Removes the containers and deletes the contents of their bind mounts.
    After running it, you are supposed to have a clean slate.
- `build` folder: Contains data needed to build some of the container images.
- `data` folder: Contains persistent data used by the respective containers. The actual data is not part of the repository.


## Services

### Nextcloud

Available as http://localhost:1181
The configured instance connects to LDAP, and comes with useful apps.
SAML integration is prepared but won't work over HTTP, as Nextcloud enforces HTTPS via its security settings.


### Rocket.Chat

Available as http://localhost:1182
Unlike other services, it doesn't recognize `admin` user, but uses the `$ROCKET_ADMIN_USERNAME`, typically `admin-rocket`.
Integrated with LDAP and configured for SAML login.


### phpLDAPadmin

Available as http://localhost:1183
Login is typically `cn=admin,dc=localhost` and the admin password.
Mostly useful to ad-hoc edits and inspection.


### Keycloak

Available as http://localhost:1184
SSO server, connects to LDAP, and mainly uses SAML to provide SSO to the other various services.


### Bureau

Available as http://localhost:1185
An admin app that aims to integrate various services, and use their respective REST APIs to ensure their mutual consistency.
You can use it to create a user (hopefully with admin privileges) using its CLI.
Then, you should be able to log in using SAML.


### Redmine

Available as http://localhost:1186
Integrated with SAML and LDAP.
SAML login works only for existing users. New users can be created by logging in via LDAP.


## How to use

### Prerequisites

- A container engine supporting the `compose` interface. Typically Docker or Podman.
- `jq` for working with JSON configuration
- OpenSSL Client for creating public-private key pairs for SAML
- `awk`, `bash` supporting associative arrays.


### Setup Steps

1. Create a file `.env` based on `.env.example`, so Docker Compose can populate variables from it.
   You may have to define a bunch of DB app passwords in there.
1. Decide whether you want to change the admin password.
   This must be updated in both `start.sh` and `.env`, as both containers and provisioning scripts use it.
1. Get an image of the `bureau` service, and make it available as `entint/bureau` to your container engine.
   Create a file `data/bureau/env` based on `data/bureau/env.example` and assign a string to the `SECRET_KEY`.


### Getting it to work

1. Typically, you will want to start from the clean slate, so run
   ```
   bash ./cleanup_data.sh
   bash ./start.sh
   ```
1. Wait until everything comes up.
1. Create a user with administrator privileges using `bureau`, as instructed.
1. Access the services on localhost, as described above.
