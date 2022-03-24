# ivansible.cert_base

Common Certbot and Letsencrypt settings.


## Requirements

None


## Variables

Available variables are listed below, along with default values.

    certbot_group: ssl-cert
Members of this unix group will have read access to certificates.
By default this is the same group as the group used by `ssl-cert` ubuntu package.

    certbot_use_docker: ...
Whether we are using dockerized certbot or installed it locally from PPA.
Default depends on `lin_use_docker`.

    certbot_script: ...
Default depends on whether we are using dockerized certbot or not.
Can be a full path to `certbot` or `certbot-docker` script.

    certbot_dir: /etc/letsencrypt
    certbot_lib_dir: /var/lib/letsencrypt
    certbot_log_dir: /var/log/letsencrypt
    certbot_hook_dir: /etc/letsencrypt/renewal-hooks
Common certbot directories.

    certbot_post_dir: .../post or .../post-docker
Subdirectory of `certbot_hook_dir` for external post-renewal scripts.
Default depends on whether we are using dockerized certbot or not.


## Handlers

None


## Tags

None


## Dependencies

- [ivansible.lin_base](https://github.com/ivansible/lin-base)
  -- common ansible handlers and default parameters


## Example Playbook

This role is only intended as a basis for inheritance.


## License

MIT


## Author Information

Created in 2021 by [IvanSible](https://github.com/ivansible)
