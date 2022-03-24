# ivansible.backup_base

This role provides common tasks for use in playbooks:
- postgresql_db_restore_encrypted.yml
  downloads encrypted database dump, decrypts and restores database
- unarchive_encrypted.yml
  downloads encrypted tarball, decrypts and unarchives
- install_scripts.yml
  installs scripts `gz-encrypt.sh` and `gz-decrypt.sh` on target

## Notes

The `main.yml` file is empty, only includes should be used.

Encryption and decryption script explicitly set `-md` message digest because
default digest has changed: openssl 1.0.x uses MD5 but 1.1+ uses SHA256.
See: https://github.com/fastlane/fastlane/issues/9542


## Requirements

None


## Variables

Available variables are listed below, along with default values.

    backup_secret: secret-123

Please override this default in inventory.


## Tags

None

## Dependencies

None


## Example Playbook

    - hosts: vagrant-boxes
      tasks:

      - include_role:
          name: ivansible.backup_base
          tasks_from: postgresql_db_restore_encrypted.yml
        vars:
          backup_url: https://backups.example.com/database.pgdump.gz.aes
          #backup_secret: some-secret
          db_name: mydata
          login_host: postgres.example.com
          #db_port: 5432
          login_password: postgres-password

      - include_role:
          name: ivansible.backup_base
          tasks_from: unarchive_encrypted.yml
        vars:
          backup_url: https://backups.example.com/archive.tar.gz.aes
          #backup_secret: some-secret
          dest: /path/to/files
          owner: username
          mode: 0644
          creates: /path/to/files/some-file.txt

      - import_role:
          name: ivansible.backup_base
          tasks_from: install_scripts.yml


## License

MIT

## Author Information

Created in 2018-2020 by [IvanSible](https://github.com/ivansible)
