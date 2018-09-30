# ivansible.db_base

This role provides database connection parameters for other asterisk roles.
It is intended to be inherited only and does not have tasks or handlers.


## Requirements

None


## Variables

Available variables are listed below, along with default values.

    srv_pg_host: localhost
    srv_pg_port: 5432
    srv_pg_admin_password: please_change
Connection parameters for PostgreSQL

    mongodb_host: localhost
    mongodb_port: 27017
    mongodb_admin_username: admin
    mongodb_admin_password: please_change
Connection parameters for MongoDB

## Tags

None


## Dependencies

None


## Example Playbook

None


## License

MIT

## Author Information

Created in 2018-2020 by [IvanSible](https://github.com/ivansible)
