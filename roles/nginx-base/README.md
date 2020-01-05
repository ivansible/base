# ivansible.nginx_base

Common Nginx and web-related handlers and defaults for other roles.


## Requirements

None


## Variables

Available variables are listed below, along with default values.

    web_user: www-data
    web_group: www-data
Unix user and group for web-based services.

    web_ports: [80, 443]
Common HTTP(S) ports for web-based services.

    mail_domain: example.com
    web_domain: example.com
Root domain for web-sites served by the remote host.

    web_force_ssl: false
If true, configure web servers so that insecure HTTP pages redirect to SSL.

    nginx_conf_dir: /etc/nginx/conf.d
Web services should put extra configuration snippets here.

    nginx_site_dir: /etc/nginx/sites-enabled
Web services should put their site definition files here.

    nginx_ssl_cert: <derived from letsencrypt setting>
    nginx_ssl_key: <derived from letsencrypt setting>
    nginx_letsencrypt_cert: ""
The first two parameters define local path of the SSL certificate and
private key assgined to the host. If the `letsencrypt_cert` parameter
is non-empty, then files will point to one of locally installed letsecnrypt
certificate/key pairs.

In case the letsencrypt setting is empty (the default), the nginx
certificate and key will default to so-called `snakeoil` self-signed
certificate, which is based off the default host name produced by the
`ssl-cert` Ubuntu package during its installation.

---

    uwsgi_base: /etc/uwsgi-emperor
    uwsgi_vassals: "{{ uwsgi_base }}/vassals"
Various `uwsgi` services should put their configurations files here.

    uwsgi_plugin_dir: /usr/lib/uwsgi/plugins
The name says it all.


## Handlers

- restart nginx service
- restart uwsgi service


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

Created in 2018-2020 by [IvanSible](https://github.com/ivansible)
