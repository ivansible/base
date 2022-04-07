#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019-2022, Ivan Andreev
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import tempfile


FERM_DIR = '/etc/ferm'

T_SEP = '\r\n'
B_SEP = b'\r\n'
B_EOL = os.linesep.encode()

ENCODING = 'utf-8'
ENCODING_ERRORS = 'strict'
try:
    if codecs.lookup_error('surrogateescape'):
        ENCODING_ERRORS = 'surrogateescape'
except (LookupError, NameError):
    pass


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


def handle_list(module, handler, zones, entity):
    zone = module.params['zone']
    if zone not in zones:
        module.fail_json(msg="Invalid zone '%s'" % zone, rc=256)
    zone = zones[zone]

    counts = dict(added=0, removed=0, updated=0, deduped=0)
    diff = dict(before='', after='')

    changed = handler(module, zone, False, counts, diff)
    for other_zone in set(zones.values()):
        if module.params['solo_zone'] and other_zone != zone:
            excluded = handler(module, other_zone, True, counts, diff)
            changed = changed or excluded

    if changed and module.params['reload']:
        reload_ferm(module)

    msg_list = []
    result = {}
    if counts['added'] > 0:
        result['added'] = counts['added']
        msg_list.append('%d %s(s) added' % (counts['added'], entity))
    if counts['removed'] > 0:
        result['removed'] = counts['removed']
        msg_list.append('%d %s(s) removed' % (counts['removed'], entity))
    if counts['updated'] > 0:
        result['updated'] = counts['updated']
        msg_list.append('%d comment(s) updated' % counts['updated'])
    if counts['deduped'] > 0:
        result['deduped'] = counts['deduped']
        msg_list.append('%d duplicate(s) removed' % counts['deduped'])
    msg = ', '.join(msg_list)

    module.exit_json(changed=changed, msg=msg, diff=diff, **result)
