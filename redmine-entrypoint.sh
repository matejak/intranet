#!/bin/bash
set -e
chown -R redmine:redmine /home/redmine/.bundle || true
exec /docker-entrypoint.sh "$@"
