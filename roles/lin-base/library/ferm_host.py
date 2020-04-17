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
short_description: Manage ferm host rules
description:
  - ...
version_added: "2.8"
options:
  host:
    description:
      - List of host/net descriptors, where each item is
        either IPv4/IPv6 address or a DNS hostname,
        optionally followed by C(/) and C(prefixlen)
        (overrides the C(prefixlen) parameter),
        then optionally followed by C(/) and C(proto)
        (overrides the C(proto) parameter).
      - Descriptors can override C(comment) by adding C(;) and custom comment.
      - Descriptors prepended by C(-) will be removed (overrides C(state)).
    type: list
    required: true
  proto:
    description:
      - Limits DNS search in case of symbolic hostname;
      - Ignored in case of IPv4 or IPv6 address.
    type: str
    choices: [ ipv4, ipv6, any ]
    default: any
    aliases: [ protocol ]
  prefixlen:
    description:
      - CIDR subnet prefix length to apply to the host address.
    type: int
  comment:
    description:
      - Host comment (optional).
    type: str
  domain:
    description:
      - C(internal) add host to the internal list;
      - C(blocked) blocks the host.
    type: str
    choices: [ internal, blocked ]
    default: external
  state:
    description:
      - Whether the rule should be added or removed.
    type: str
    choices: [ absent, present ]
    default: present
  solo:
    description:
      - If this is I(true) and C(state) is I(present),
        then adding item to a domain will remove it from other domains.
      - This has no effect if item C(state) is I(absent).
    type: bool
    default: false
  reload:
    description:
      - Reload firewall rules in case of changes.
    type: bool
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
- name: Block the host
  ferm_host:
    host: badguy.com
    domain: blocked
'''

import os
import re
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes, to_native

domain_to_extension = {
    'internal': 'int',
    'blocked': 'block',
}


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


def reload_ferm(module):
    if os.path.isdir('/proc/vz'):
        cmd = ['systemctl', 'reload-or-restart', 'ferm.service']
    else:
        cmd = ['ferm-ipset']
    rc, stdout, stderr = module.run_command(cmd)
    if rc:
        module.fail_json(msg='Failed to reload ferm',
                         rc=rc, stdout=stdout, stderr=stderr)


def handle_hosts(module, domain, exclude, counts, diff):
    config_path = ferm_config(module, 'hosts.%s' % domain_to_extension[domain])
    with open(config_path, 'rb') as f:
        b_lines = f.readlines()

    if module._diff and not exclude:
        diff['before'] = to_native(b''.join(b_lines))

    b_linesep = to_bytes(os.linesep, errors='surrogate_or_strict')
    valid_host = r'^(([0-9]{1,3}[.]){3}[0-9]{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]*|[0-9a-zA-Z_.-]+)$'
    changed = False

    for host in module.params['host']:
        host = str(host).strip() if host else ''
        proto = module.params['proto']
        prefixlen = module.params['prefixlen']
        comment = module.params['comment'] or ''
        add = module.params['state'] == 'present'

        if host.startswith('-'):
            host = host[1:].strip()
            add = False
        if not host:
            continue

        if exclude:
            if add:
                add = False
            else:
                continue

        split = re.match(r'^([^;]*);(.*)$', host)
        if split:
            host, comment = split.group(1).strip(), split.group(2).strip()
        b_comment = to_bytes(comment.rstrip('\r\n'), errors='surrogate_or_strict')

        split = re.match(r'^(.+)/(ipv4|ipv6|any)$', host)
        if split:
            host, proto = split.group(1), split.group(2)
        split = re.match(r'^(.+)/([0-9]+)$', host)
        if split:
            host, prefixlen = split.group(1), int(split.group(2))

        if not re.match(valid_host, host):
            module.fail_json(rc=256, msg="Invalid host '%s'" % host)
        if prefixlen is not None and (prefixlen < 0 or prefixlen > 128):
            module.fail_json(rc=256, msg="Invalid prefixlen %d" % prefixlen)

        line = host
        if prefixlen is not None:
            line = '%s/%d' % (line, prefixlen)
        if proto != 'any':
            line = '%s/%s' % (line, proto)

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
                    counts['deduped'] += 1
                    changed = True
                elif match and not found:
                    found = True
                    if not b_comment or b_comment == match.group(2):
                        b_lines.append(b_cur_line)
                    else:
                        b_lines.append(b_new_line + b_linesep)
                        counts['updated'] += 1
                        changed = True
                else:
                    b_lines.append(b_cur_line)

            if not found:
                # add to the end of file ensuring there's a newline before it
                if b_lines and not b_lines[-1][-1:] in (b'\n', b'\r'):
                    b_lines.append(b_linesep)
                b_lines.append(b_new_line + b_linesep)
                counts['added'] += 1
                changed = True
        else:
            orig_len = len(b_lines)
            b_lines = [l for l in b_lines
                       if not b_regex.match(l.rstrip(b'\r\n'))]
            removed = orig_len - len(b_lines)
            counts['removed'] += removed
            if removed > 0:
                changed = True

    if changed and not module.check_mode:
        write_changes(module, config_path, b_lines)

    if module._diff and not exclude:
        diff['after'] = to_native(b''.join(b_lines))

    return changed


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='list', required=True),
            proto=dict(type='str', default='any', choices=['ipv4', 'ipv6', 'any'],
                       aliases=['protocol']),
            prefixlen=dict(type='int'),
            comment=dict(type='str'),
            domain=dict(type='str', default='internal',
                        choices=['internal', 'blocked']),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            solo=dict(type='bool', default=False),
            reload=dict(type='bool', default=True),
            ferm_dir=dict(type='str', default='/etc/ferm'),
        ),
        supports_check_mode=True,
    )

    domain = module.params['domain']
    if domain not in domain_to_extension:
        module.fail_json(rc=256, msg='Invalid domain argument')

    counts = dict(added=0, removed=0, updated=0, deduped=0)
    diff = dict(before='', after='')

    changed = handle_hosts(module, domain, False, counts, diff)

    if module.params['solo']:
        # remove item from other domains
        for other_domain in domain_to_extension.keys():
            if other_domain == domain:
                continue
            excluded = handle_hosts(module, other_domain, True, counts, diff)
            changed = changed or excluded

    if changed and module.params['reload'] and not module.check_mode:
        reload_ferm(module)

    msg_list = []
    result = {}
    if counts['added'] > 0:
        result['added'] = counts['added']
        msg_list.append('%d host(s) added' % counts['added'])
    if counts['removed'] > 0:
        result['removed'] = counts['removed']
        msg_list.append('%d host(s) removed' % counts['removed'])
    if counts['updated'] > 0:
        result['updated'] = counts['updated']
        msg_list.append('%d comment(s) updated' % counts['updated'])
    if counts['deduped'] > 0:
        result['deduped'] = counts['deduped']
        msg_list.append('%d duplicate(s) removed' % counts['deduped'])
    msg = ', '.join(msg_list)

    module.exit_json(changed=changed, msg=msg, diff=diff, **result)


if __name__ == '__main__':
    main()
