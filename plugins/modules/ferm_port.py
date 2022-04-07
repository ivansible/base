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
        or C(:)-separated port range, optionally followed
        by C(/) and I(proto) (overrides the C(proto) parameter).
      - Descriptors can override C(comment) by adding C(;) and custom comment.
      - Descriptors prepended by C(-) will be removed (overrides C(state)).
    type: list
    required: true
  proto:
    description:
      - Default protocol for listed ports.
    type: str
    choices: [ any, tcp, udp ]
    default: any
    aliases: [ protocol ]
  zone:
    description:
      - C(external) opens the port for all hosts;
      - C(internal) opens the port for internal hosts only;
      - C(media) opens the port for both internal and media hosts;
      - C(blocked) blocks the port from external hosts.
    type: str
    choices: [ external, internal, media, blocked ]
    default: external
    aliases: [ domain ]
  state:
    description:
      - Whether the rule should be added or removed.
    type: str
    choices: [ absent, present ]
    default: present
  solo_zone:
    description:
      - If this is I(true) and C(state) is I(present),
        then adding item to a zone will remove it from other zones.
      - This has no effect if item C(state) is I(absent).
    type: bool
    default: false
    aliases: [ solo ]
  solo_comment:
    description:
      - If this is I(true) and C(state) is I(present),
        then adding an item will remove other items with the same comment.
      - This has no effect if C(state) is I(absent) or C(comment) is empty.
    type: bool
    default: false
  reload:
    description:
      - Reload firewall rules in case of changes.
    type: bool
    default: true
  backup:
    description:
      - Backup changed configurations.
    type: bool
    default: false
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
    zone: internal
'''

import re

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.ivansible.base.plugins.module_utils.ferm import (
    FERM_DIR,
    T_SEP,
    B_SEP,
    B_EOL,
    to_bytes,
    to_text,
    ferm_config,
    write_changes,
    handle_list,
)

ZONES = {
    'external': 'ext',
    'ext': 'ext',
    'internal': 'int',
    'int': 'int',
    'media': 'media',
    'blocked': 'block',
    'block': 'block',
}

VALID_PORT = r'^[0-9]{1,5}([:-][0-9]{1,5})?$'


def handle_ports(module, zone, exclude, counts, diff):
    path = ferm_config(module, 'ports.%s' % ZONES[zone])
    with open(path, 'rb') as f:
        b_lines = f.readlines()

    if module._diff and not exclude:
        diff['before'] = to_text(b''.join(b_lines))

    changed = False

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

        if exclude:
            if add:
                add = False
            else:
                continue

        split = re.match(r'^([^#;~]*)[#;~](.*)$', port)
        if split:
            port, comment = split.group(1).strip(), split.group(2).strip()
            if not port:
                continue
        comment = comment.rstrip(T_SEP).replace('~', ' ')
        b_comment = to_bytes(comment)

        split = re.match(r'^([^/]+)/(any|tcp|udp)$', port)
        if split:
            port, proto = split.group(1), split.group(2)

        if not re.match(VALID_PORT, port):
            module.fail_json(msg="Invalid port '%s'" % port, rc=256)

        port = port.replace('-', ':')
        line = port if proto == 'any' else '%s/%s' % (port, proto)
        b_line = to_bytes(line)

        b_new_line = b_line
        if b_comment:
            b_new_line += b' # ' + b_comment

        regexp = r'^\s*(%s)\s*(?:#+\s*(.*)\s*)?$' % line
        b_regex = re.compile(to_bytes(regexp))

        solo_comment = module.params['solo_comment'] and b_comment
        if solo_comment:
            comm_regexp = r'^\s*(.*)\s*#+\s*(%s)\s*$' % comment
            b_comm_re = re.compile(to_bytes(comm_regexp))

        if add:
            b_prev_lines = b_lines
            b_lines = []
            found = False
            comm_found = False

            for b_cur_line in b_prev_lines:
                match = b_regex.match(b_cur_line.rstrip(B_SEP))
                if match and (found or comm_found):
                    # remove duplicates
                    counts['deduped'] += 1
                    changed = True
                elif match and not found:
                    found = True
                    if not b_comment or b_comment == match.group(2):
                        b_lines.append(b_cur_line)
                    else:
                        b_lines.append(b_new_line + B_EOL)
                        counts['updated'] += 1
                        changed = True
                elif solo_comment:
                    comm_match = b_comm_re.match(b_cur_line.rstrip(B_SEP))
                    if comm_match and comm_found:
                        counts['deduped'] += 1
                        changed = True
                    elif comm_match and not comm_found:
                        comm_found = True
                        if b_line == comm_match.group(1):
                            b_lines.append(b_cur_line)
                        else:
                            b_lines.append(b_new_line + B_EOL)
                            counts['updated'] += 1
                            changed = True
                    else:
                        b_lines.append(b_cur_line)
                else:
                    b_lines.append(b_cur_line)

            if not (found or comm_found):
                # add to the end of file ensuring there's a newline before it
                if b_lines and not b_lines[-1][-1:] in B_SEP:
                    b_lines.append(B_EOL)
                b_lines.append(b_new_line + B_EOL)
                counts['added'] += 1
                changed = True
        else:
            orig_len = len(b_lines)
            b_lines = [ln for ln in b_lines
                       if not b_regex.match(ln.rstrip(B_SEP))]
            removed = orig_len - len(b_lines)
            counts['removed'] += removed
            if removed > 0:
                changed = True

    if changed:
        write_changes(module, path, b_lines)

    if module._diff and not exclude:
        diff['after'] = to_text(b''.join(b_lines))

    return changed


def main():
    module = AnsibleModule(
        argument_spec=dict(
            port=dict(type='list', required=True),
            proto=dict(type='str', default='any', choices=['any', 'tcp', 'udp'],
                       aliases=['protocol']),
            comment=dict(type='str'),
            zone=dict(type='str', default='external', aliases=['domain'],
                      choices=['external', 'internal', 'media', 'blocked']),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            solo_zone=dict(type='bool', default=False, aliases=['solo']),
            solo_comment=dict(type='bool', default=False),
            reload=dict(type='bool', default=True),
            backup=dict(type='bool', default=False),
            ferm_dir=dict(type='str', default=FERM_DIR),
        ),
        supports_check_mode=True,
    )
    handle_list(module, handle_ports, ZONES, 'port')


if __name__ == '__main__':
    main()
