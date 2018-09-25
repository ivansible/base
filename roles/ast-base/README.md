# ivansible.asterisk_base

This role provides common defaults and handlers for asterisk roles.
It is intended to be inherited only and does not have `main.yml`.


## Requirements

None


## Variables

Available variables are listed below, along with default values.

    ast_reset: no
If yes, the role will reset configuration before adjusting particular options.
If no, only adjustments will be performed.

    ast_experimental: no
This switch enables experimental features. Meaning depends on particular role.

    ast_ssl_cert: /etc/ssl/certs/ssl-cert-snakeoil.pem
    ast_ssl_key: /etc/ssl/private/ssl-cert-snakeoil.key
Paths of SSL certificate and private key files that Asterisk
will use for incoming SIP TLS and AMI HTTPS conections.
By default these are inherited from `nginx` certificate defined by the role
[ivansible.nginx_base](https://github.com/ivansible/nginx-base#variables)
that in turn defaults to a so-called _snakoil_ certificate,
which is generated on fly by the `ssl-cert` Ubuntu package.

    ast_domains: "{{ [ ansible_fqdn ] }}"
The list of domains that asterisk will respond to. The first domain is default.

    ast_dialplan_hints: yes
Allows or disables dependant roles to use `peer is alive` hints in dialplan.

    ast_default_language: en
Chooses language for asterisk sound prompts: `en` or `ru`.
Meaning depends on a particular role.

    ast_default_codecs: g729,g722,ulaw,alaw
Comma-delimited list of codecs. Meaning depends on a particular role.

    ast_qualify_value: "yes"

By default qualify timeout is 1 second (`yes`). However, sometimes you need
to increase the timeout, e.g. set this value to `3000` (milliseconds).

    ast_pg_host: localhost
    ast_pg_port: 5432
    ast_pg_dbname: asterisk
    ast_pg_user: asterisk
    ast_pg_pass: secret
Database connection parameters.

    ast_local_dir: /usr/local/asterisk
Directory for custom asterisk utilities, sounds etc.


## Tags

None


## Handlers

These handlers are defined for reuse in dependant roles:
- restart asterisk service
- reload asterisk service

A restart forces Asterisk to load and initialize all modules, and a following
reload will wait until the initialization finishes resulting in a wait.
Please use either restart or reload handler throughout a particular role.
Normally `asterisk_core` will use the _restart_ handler, while `asterisk_soho`
and other roles will use the _reload_ handler.


## Dependencies

This role depends on:
  - [ivansible.lin_base](https://github.com/ivansible/lin-base)
    -- for some common settings
  - [ivansible.nginx_base](https://github.com/ivansible/nginx-base#variables)
    -- for default ssl certificate/key file paths

This role is inherited by:
  - [ivansible.asterisk_core](https://github.com/ivansible/asterisk-core)
  - [ivansible.asterisk_soho](https://github.com/ivansible/asterisk-soho)
  - [ivansible.asterisk_providers](https://github.com/ivansible/asterisk-providers)
  - [ivansible.asterisk_billing](https://github.com/ivansible/asterisk-billing)


## Example Playbook

This role is only intended as a basis for inheritance.


## License

MIT

## Author Information

Created in 2018 by [IvanSible](https://github.com/ivansible)
