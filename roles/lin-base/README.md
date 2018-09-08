# lin_base

Common ansible handlers and defaults for using in other roles.


## Requirements

None


## Variables

Available variables are listed below, along with default values.


    hide_secrets: yes
TBD

    web_group: www-data
TBD

---

    allow_sysctl: yes
TBD

    lin_ssh_port: 22
TBD

    lin_ssh_keys_files: <playbook_dir>/files/lin-ssh-*.key'
TBD

---

    web_user: www-data
TBD

    web_ports: [ 80, 443 ]
TBD

---

    mail_domain: example.com
TBD

    web_domain: example.com
TBD

    web_force_ssl: no
TBD

---

    systemd_dir: /etc/systemd/system
TBD

    local_bin: /usr/local/bin
TBD

---

    nginx_conf_dir: /etc/nginx/conf.d
TBD

    nginx_site_dir: /etc/nginx/sites-enabled
TBD

---

    uwsgi_base: /etc/uwsgi-emperor
TBD

    uwsgi_vassals: "{{ lin_uwsgi_base }}/vassals"
TBD

    uwsgi_plugin_dir: /usr/lib/uwsgi/plugins
TBD


## Example Playbook

None


## License

MIT


## Author Information

Created in 2018 by [IvanSible](https://github.com/ivansible)
