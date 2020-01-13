#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019-2020, Ivan Andreev
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'core'}


DOCUMENTATION = r'''
---
module: ferm_port
short_description: Manage ferm port rules
description:
  - ...
version_added: "2.8"
options:
  port:
    description:
      - List of port descriptors, where each descriptor is a port number
        or C(-)-separated port range, optionally followed by C(/)
        and I(proto) (overrides the C(proto) parameter).
      - Descriptors can override C(comment) by adding C(;) and custom comment.
      - Descriptors prepended by C(-) will be removed (overrides C(state)).
    type: list
    required: true
  proto:
    description:
      - Default protocol for listed ports.
    type: str
    choices: [ tcp, udp, any ]
    default: any
    aliases: [ protocol ]
  domain:
    description:
      - C(external) opens the port for all hosts;
      - C(internal) opens the port for internal hosts only;
      - C(blocked) blocks the port from external hosts.
    type: str
    choices: [ external, internal, blocked ]
    default: external
  state:
    description:
      - Whether the rule should be added or removed.
    type: str
    choices: [ absent, present ]
    default: present
  reload:
    description:
      - Reload firewall rules in case of changes.
    default: true
  ferm_dir:
    description:
      - Ferm configuration directory.
    type: str
    default: /etc/ferm
seealso:
- module: ferm_host
- module: ferm_port
- module: ferm_rule
author:
    - Ivan Adnreev (@ivandeex)
'''

EXAMPLES = r'''
- name: Open SSH port for internal hosts
  ferm_port:
    port: 22
    proto: tcp
    domain: internal
'''

import os
import re
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes, to_native


def ferm_config(module, filename):

    ferm_dir = module.params['ferm_dir']
    dest = os.path.join(ferm_dir, filename)
    b_dest = to_bytes(dest, errors='surrogate_or_strict')
    if not os.path.exists(b_dest):
        module.fail_json(rc=257, msg='Config file %s does not exist!' % dest)

    b_path = os.path.realpath(b_dest)
    return to_native(b_path, errors='surrogate_or_strict')


def write_changes(module, config_path, b_lines):
    tmpfd, tmpfile = tempfile.mkstemp()
    with os.fdopen(tmpfd, 'wb') as f:
        f.writelines(b_lines)

    module.atomic_move(tmpfile, config_path, unsafe_writes=False)

    if module.params['reload']:
        cmd = ['systemctl', 'reload-or-restart', 'ferm.service']
        rc, stdout, stderr = module.run_command(cmd)
        if rc:
            module.fail_json(msg='Failed to reload ferm',
                             rc=rc, stdout=stdout, stderr=stderr)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            port=dict(type='list', required=True),
            proto=dict(type='str', default='any', choices=['tcp', 'udp', 'any'],
                       aliases=['protocol']),
            comment=dict(type='str'),
            domain=dict(type='str', default='external',
                        choices=['external', 'internal', 'blocked']),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            reload=dict(type='bool', default=True),
            ferm_dir=dict(type='str', default='/etc/ferm'),
        ),
        supports_check_mode=True,
    )

    domain = module.params['domain']
    domain_to_extension = {
        'external': 'ext',
        'internal': 'int',
        'blocked': 'block',
    }
    if domain not in domain_to_extension:
        module.fail_json(rc=256, msg='Invalid domain argument')

    config_path = ferm_config(module, 'ports.%s' % domain_to_extension[domain])
    with open(config_path, 'rb') as f:
        b_lines = f.readlines()

    diff = dict(before='', after='')
    if module._diff:
        diff['before'] = to_native(b''.join(b_lines))

    b_linesep = to_bytes(os.linesep, errors='surrogate_or_strict')

    changed = False
    added = 0
    removed = 0
    updated = 0
    deduped = 0
    res = {}
    msg = ''
    valid_port = r'^[0-9]+(-[0-9]+)?$'

    for port in module.params['port']:
        port = str(port).strip() if port else ''
        proto = module.params['proto']
        comment = module.params['comment'] or ''
        add = module.params['state'] == 'present'

        if port.startswith('-'):
            port = port[1:].strip()
            add = False
        if not port:
            continue

        split = re.match(r'^([^;]*);(.*)$', port)
        if split:
            port, comment = split.group(1).strip(), split.group(2).strip()
        b_comment = to_bytes(comment.rstrip('\r\n'), errors='surrogate_or_strict')

        split = re.match(r'^([^/]+)/(tcp|udp|any)$', port)
        if split:
            port, proto = split.group(1), split.group(2)

        if not re.match(valid_port, port):
            module.fail_json(rc=256, msg="Invalid port '%s'" % port)

        line = port if proto == 'any' else '%s/%s' % (port, proto)
        b_line = to_bytes(line, errors='surrogate_or_strict')

        b_new_line = b_line
        if b_comment:
            b_new_line += b' # ' + b_comment

        regexp = r'^\s*(%s)\s*(?:#+\s*(.*)\s*)?$' % line
        b_regex = re.compile(to_bytes(regexp, errors='surrogate_or_strict'))

        if add:
            b_prev_lines = b_lines
            b_lines = []
            found = False

            for b_cur_line in b_prev_lines:
                match = b_regex.match(b_cur_line.rstrip(b'\r\n'))
                if match and found:
                    # remove duplicates
                    deduped += 1
                    changed = True
                elif match and not found:
                    found = True
                    if not b_comment or b_comment == match.group(2):
                        b_lines.append(b_cur_line)
                    else:
                        b_lines.append(b_new_line + b_linesep)
                        updated += 1
                        changed = True
                else:
                    b_lines.append(b_cur_line)

            if not found:
                # add to the end of file ensuring there's a newline before it
                if b_lines and not b_lines[-1][-1:] in (b'\n', b'\r'):
                    b_lines.append(b_linesep)
                b_lines.append(b_new_line + b_linesep)
                added += 1
                changed = True
        else:
            orig_len = len(b_lines)
            b_lines = [l for l in b_lines
                       if not b_regex.match(l.rstrip(b'\r\n'))]
            removed += orig_len - len(b_lines)

    msg_list = []
    if added > 0:
        res['added'] = added
        msg_list.append('%d port(s) added' % added)
    if removed > 0:
        changed = True
        res['removed'] = removed
        msg_list.append('%d port(s) removed' % removed)
    if updated > 0:
        res['updated'] = updated
        msg_list.append('%d comment(s) updated' % updated)
    if deduped > 0:
        res['deduped'] = deduped
        msg_list.append('%d duplicate(s) removed' % deduped)
    msg = ', '.join(msg_list)

    if changed and not module.check_mode:
        write_changes(module, config_path, b_lines)

    if module._diff:
        diff['after'] = to_native(b''.join(b_lines))

    module.exit_json(changed=changed, msg=msg, diff=diff, **res)


if __name__ == '__main__':
    main()
