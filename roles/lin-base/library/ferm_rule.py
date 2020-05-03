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
  name:
    description:
      - Rule name.
    type: str
    required: true
  rule:
    description:
      - Text of firewall rules.
      - Required if I(state) is C(present).
    type: str
    aliases: [ rules, snippet ]
  hook:
    description:
      - Hook to insert the rule in.
    type: str
    choices: [ custom, input, forward, internal, external ]
    default: input
  prio:
    description:
      - Relative rule order from 0 to 99.
    type: int
    default: 50
    aliases: [ priority ]
  state:
    description:
      - Whether the rule should be added or removed.
    type: str
    choices: [ absent, present ]
    default: present
  backup:
    description:
      - Whether backup of existing rule should be saved.
    type: bool
    default: false
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
- name: Block port 9999
  ferm_rule:
    name: block-sample-port
    rule: |
      proto tcp dport 9999 DROP;
    hook: input
    prio: 55
'''

import os
import re
import glob
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes

DEFAULT_PRIO = 50


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            rule=dict(type='str', no_log=True, aliases=['rules', 'snippet']),
            hook=dict(type='str', default='custom',
                      choices=['custom', 'input', 'forward', 'internal', 'external']),
            prio=dict(type='int', default=DEFAULT_PRIO, aliases=['priority']),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            backup=dict(type='bool', default=False),
            reload=dict(type='bool', default=True),
            ferm_dir=dict(type='str', default='/etc/ferm'),
        ),
        supports_check_mode=True,
        required_if=[('state', 'present', ['rule'])],
    )

    name = module.params['name']
    if re.search(r'^\d+-|[\s\\\/]|\.ferm$', name):
        module.fail_json(msg="Invalid rule name: '%s'" % name)

    prio = module.params['prio']
    if prio < 0 or prio > 99:
        module.fail_json(msg='Invalid rule prio: %d' % prio)

    hook = module.params['hook']
    hook_dir = os.path.join(module.params['ferm_dir'], hook)
    if not os.path.isdir(hook_dir) or not os.access(hook_dir, os.W_OK):
        module.fail_json(msg='Directory is absent or not writable: ' + hook_dir)

    new_path = os.path.join(hook_dir, '%02d-%s.ferm' % (prio, name))
    b_new_path = to_bytes(new_path, errors='surrogate_or_strict')

    path_glob = os.path.join(hook_dir, '*-%s.ferm' % name)
    regexp = os.path.join(re.escape(hook_dir), '[0-9]{2}-%s.ferm' % re.escape(name))
    path_regex = re.compile('^%s$' % regexp)
    old_list = sorted(p for p in glob.glob(path_glob) if path_regex.match(p))

    exists = os.path.exists(b_new_path)
    if exists and not os.path.isfile(b_new_path):
        module.fail_json(msg='Destination is not a regular file: ' + new_path)
    if exists and not os.access(b_new_path, os.W_OK):
        module.fail_json(msg='Destination is not writable: ' + new_path)

    if exists:
        old_list.remove(new_path)  # must be present in the list
        old_path = new_path
    elif old_list:
        old_path = old_list.pop(0)  # first in sort order
        exists = True

    changed = False
    msg = ''
    backup = module.params['backup']
    backup_file = None
    state = module.params['state']

    if state == 'absent' and exists:
        changed = True
        if not module.check_mode:
            if backup:
                backup_file = module.backup_local(old_path)
            os.remove(to_bytes(old_path, errors='surrogate_or_strict'))
            msg = 'Rule removed: %s' % name
            if old_path != new_path:
                msg += ' (as old priority)'

    if state == 'present':
        rule = module.params['rule']
        if rule is None:
            module.fail_json(msg='Please provide the rule')
        b_rule = to_bytes(rule)

        if exists:
            with open(old_path, 'rb') as f:
                b_orig_rule = f.read()
            changed = b_rule != b_orig_rule or old_path != new_path
        else:
            changed = True

        if changed and not module.check_mode:
            tmpfd, tmpfile = tempfile.mkstemp()
            with os.fdopen(tmpfd, 'wb') as f:
                f.write(b_rule)

            if exists and backup:
                backup_file = module.backup_local(old_path)
            if exists and old_path != new_path:
                os.remove(to_bytes(old_path, errors='surrogate_or_strict'))

            module.atomic_move(tmpfile, new_path, unsafe_writes=False)
            msg = 'Rule saved: %s' % name
            if exists and old_path != new_path:
                msg += ' (as new priority)'

            module.set_mode_if_different(new_path, '0640', changed)
            module.set_owner_if_different(new_path, 'root', changed)
            module.set_group_if_different(new_path, 'root', changed)

    result = {'path': new_path}
    if backup_file:
        result['backup'] = backup_file
    if exists and old_path != new_path:
        result['old_path'] = old_path

    if old_list:
        if not module.check_mode:
            for path in old_list:
                os.remove(to_bytes(path, errors='surrogate_or_strict'))
        result['num_duplicates'] = len(old_list)
        if not msg:
            msg = 'Rule unchanged'
        msg += ', %d duplicate(s) removed' % len(old_list)
        changed = True

    if changed and module.params['reload'] and not module.check_mode:
        cmd = ['systemctl', 'reload-or-restart', 'ferm.service']
        rc, stdout, stderr = module.run_command(cmd)
        if rc:
            module.fail_json(msg='Failed to reload ferm',
                             rc=rc, stdout=stdout, stderr=stderr)

    module.exit_json(changed=changed, msg=msg, **result)


if __name__ == '__main__':
    main()
