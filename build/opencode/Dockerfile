FROM ghcr.io/anomalyco/opencode:latest 

ENV PYTHONUNBUFFERED=1
RUN true \
	&& apk add --update --no-cache python3 py3-pip py3-virtualenv py3-mypy py3-sphinx \
		py3-sqlalchemy py3-ldap3  \
		py3-pytest py3-pytest-asyncio py3-pytest-dependency \
		ruff git bash make ripgrep \
	&& true

WORKDIR /work

RUN true && \
	pip install --break-system-packages nc-py-api python-redmine rocketchat-api \
	&& true
