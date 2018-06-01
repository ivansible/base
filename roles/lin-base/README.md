# Role lin-base

Common ansible handlers and defaults for use in other roles.


## Requirements

None


## Variables

Available variables are listed below, along with default values.


    lin_hide_secrets: yes
TBD

    lin_allow_sysctl: yes
TBD

    lin_ssh_port: 22
TBD

---

    lin_web_user: www-data
TBD

    lin_web_group: www-data
TBD

    lin_web_ports: [ 80, 443 ]
TBD

---

    lin_mail_domain: example.com
TBD

    lin_web_domain: example.com
TBD

    lin_web_force_ssl: no
TBD

---

    lin_systemd_dir: /etc/systemd/system
TBD

    lin_local_bin: /usr/local/bin
TBD

---

    lin_nginx_conf_dir: /etc/nginx/conf.d
TBD

    lin_nginx_site_dir: /etc/nginx/sites-enabled
TBD

---

    lin_uwsgi_base: /etc/uwsgi-emperor
TBD

    lin_uwsgi_vassals: "{{ lin_uwsgi_base }}/vassals"
TBD

    lin_uwsgi_plugin_dir: /usr/lib/uwsgi/plugins
TBD


## Example Playbook

None


## License

MIT


## Author Information

Created in 2018 by [IvanSible](https://github.com/ivansible)
