FROM redmine:6

RUN true \
        && cd /usr/src/redmine \
        && mkdir -p plugins \
        && git clone https://github.com/alphanodes/additionals.git plugins/additionals \
        && git clone https://github.com/alphanodes/redmine_saml.git plugins/redmine_saml \
        && git clone https://github.com/farend/redmine_message_customize.git plugins/redmine_message_customize\
        && true

RUN bundle install
RUN mkdir -p /home/redmine/.bundle \
    && chown -R redmine:redmine /home/redmine
