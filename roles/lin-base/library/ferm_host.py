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
    choices: [ any, ipv4, ipv6 ]
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
  zone:
    description:
      - C(internal) add host to the internal list;
      - C(blocked) blocks the host.
    type: str
    choices: [ internal, blocked, nat ]
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
- name: Block a host
  ferm_host:
    host: badguy.com
    zone: blocked
'''

import os
import re
import tempfile

from ansible.module_utils.basic import AnsibleModule

FERM_DIR = '/etc/ferm'

ZONES = {
    'internal': 'int',
    'int': 'int',
    'blocked': 'block',
    'block': 'block',
    'nat': 'nat',
}

ENCODING = 'utf-8'
ENCODING_ERRORS = 'strict'
try:
    if codecs.lookup_error('surrogateescape'):
        ENCODING_ERRORS = 'surrogateescape'
except (LookupError, NameError):
    pass

VALID_HOST = r'^(([0-9]{1,3}[.]){3}[0-9]{1,3}' \
             r'|[0-9a-fA-F:]*:[0-9a-fA-F:]*' \
             r'|[0-9a-zA-Z_.-]+)$'

T_SEP = '\r\n'
B_SEP = b'\r\n'
B_EOL = os.linesep.encode()


def to_bytes(obj):
    if isinstance(obj, bytes):
        return obj
    elif isinstance(obj, str):
        return obj.encode(ENCODING, ENCODING_ERRORS)
    else:
        raise TypeError('obj must be a string type')


def to_text(obj):
    if isinstance(obj, str):
        return obj
    elif isinstance(obj, bytes):
        return obj.decode(ENCODING, ENCODING_ERRORS)
    else:
        raise TypeError('obj must be a string type')


def ferm_config(module, filename):
    dest = os.path.join(module.params['ferm_dir'], filename)
    if not os.path.exists(to_bytes(dest)):
        module.fail_json(msg="Config file '%s' does not exist!" % dest, rc=257)
    return to_text(os.path.realpath(to_bytes(dest)))


def write_changes(module, path, b_lines):
    if module.check_mode:
        return
    if module.params['backup']:
        module.run_command(['cp', '-a', path, path + '~'])
    tmpfd, tmpfile = tempfile.mkstemp()
    with os.fdopen(tmpfd, 'wb') as f:
        f.writelines(b_lines)
    module.atomic_move(tmpfile, path, unsafe_writes=False)


def reload_ferm(module):
    if module.check_mode:
        return
    if os.path.isdir('/proc/vz'):
        cmd = ['systemctl', 'reload-or-restart', 'ferm.service']
    else:
        cmd = ['ferm-ipset']
    rc, stdout, stderr = module.run_command(cmd)
    if rc:
        module.fail_json(msg='Failed to reload ferm',
                         rc=rc, stdout=stdout, stderr=stderr)


def handle_hosts(module, zone, exclude, counts, diff):
    path = ferm_config(module, 'hosts.%s' % ZONES[zone])
    with open(path, 'rb') as f:
        b_lines = f.readlines()

    if module._diff and not exclude:
        diff['before'] = to_text(b''.join(b_lines))

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

        split = re.match(r'^([^#;~]*)[#;~](.*)$', host)
        if split:
            host, comment = split.group(1).strip(), split.group(2).strip()
            if not host:
                continue
        comment = comment.rstrip(T_SEP).replace('~', ' ')
        b_comment = to_bytes(comment)

        split = re.match(r'^(.+)/(any|ipv4|ipv6)$', host)
        if split:
            host, proto = split.group(1), split.group(2)
        split = re.match(r'^(.+)/([0-9]+)$', host)
        if split:
            host, prefixlen = split.group(1), int(split.group(2))

        if not re.match(VALID_HOST, host):
            module.fail_json(msg="Invalid host '%s'" % host, rc=256)
        if prefixlen is not None and (prefixlen < 0 or prefixlen > 128):
            module.fail_json(msg="Invalid prefixlen %d" % prefixlen, rc=256)

        line = host
        if prefixlen is not None:
            line = '%s/%d' % (line, prefixlen)
        if proto != 'any':
            line = '%s/%s' % (line, proto)

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
            b_lines = [l for l in b_lines
                       if not b_regex.match(l.rstrip(B_SEP))]
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
            host=dict(type='list', required=True),
            proto=dict(type='str', default='any', choices=['any', 'ipv4', 'ipv6'],
                       aliases=['protocol']),
            prefixlen=dict(type='int'),
            comment=dict(type='str'),
            zone=dict(type='str', default='internal', aliases=['domain'],
                      choices=['internal', 'blocked', 'nat']),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            solo_zone=dict(type='bool', default=False, aliases=['solo']),
            solo_comment=dict(type='bool', default=False),
            reload=dict(type='bool', default=True),
            backup=dict(type='bool', default=False),
            ferm_dir=dict(type='str', default=FERM_DIR),
        ),
        supports_check_mode=True,
    )

    zone = module.params['zone']
    if zone not in ZONES:
        module.fail_json(msg="Invalid zone '%s'" % zone, rc=256)
    zone = ZONES[zone]

    counts = dict(added=0, removed=0, updated=0, deduped=0)
    diff = dict(before='', after='')

    changed = handle_hosts(module, zone, False, counts, diff)
    for other_zone in set(ZONES.values()):
        if module.params['solo_zone'] and other_zone != zone:
            excluded = handle_hosts(module, other_zone, True, counts, diff)
            changed = changed or excluded

    if changed and module.params['reload']:
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
