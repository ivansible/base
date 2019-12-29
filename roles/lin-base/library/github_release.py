#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Ivan Andreev <ivandeex@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: github_release
author: "Ivan Andreev (@ivandeex)"
short_description: Returns links to github release artifacts
description:
  - Interacts with github
  - Finds latest release tag for given repository
  - Returns links to release artifacts
  - Runs local comands to find installed package version
version_added: "1.0"
options:
  repo:
    description:
      - Describes github repository to query
      - Either a combined string C(USERNAME/REPOSITORY:RELEASE)
      - Or just C(USERNAME/REPOSITORY) (then C(release) argument must be provided)
      - Or just C(REPOSITORY) (then C(release) and C(user) arguments must be provided)
    type: str
    required: true
    aliases:
      - repository
  user:
    description:
      - Owner of the github repository
    type: str
    aliases:
      - owner
  release:
    description:
      - A release to seek, either C(latest) or a git tag
    type: str
    default: latest
  only_latest:
    description:
      - If true and C(release) is C(latest), the module will access github to request the latest release tag
      - If true and C(release) is not C(latest), the module will build release URL without accessing github
      - If false, the module will always access github to check whether given release exists
    type: bool
    default: true
  creates:
    description:
      - If C(creates) is defined and the given file exists, the module will skip actions and mark release as not changed
      - If C(creates) is not defined or the given file does not exist, the module will perform its actions and mark the release as changed
    type: path
  reinstall:
    description:
      - If C(creates) is defined and the given filename exists but C(reinstall) is true, the module will still mark the release as changed
    type: bool
    default: false
  shout:
    description:
      - Defines when should the module print a warning message about detected release
    type: str
    choices:
      - latest
      - always
      - never
    default: latest
    aliases:
      - shout_if
  template:
    description:
      - If C(template) is not provided, the module returns the resolved repository url like C(https://github.com/USERNAME/REPOSITORY)
      - 'If C(template) is provided, it must contain the following placeholders:'
      - 'C({ver}) - detected release (with or without first "v", depending on the C(stripv) option)'
      - 'C({repo_url}) - link to the repository like C(https://github.com/USERNAME/REPOSITORY)'
      - 'C({release_url}) - link to the resolved release like C(https://github.com/USERNAME/REPOSITORY/releases/tag/RELEASE)'
      - 'C({download_url}) - link to the artifact download folder for the release like C(https://github.com/USERNAME/REPOSITORY/releases/download/RELEASE)'
    type: str
    aliases:
      - url_template
  stripv:
    description:
      - Defines whether first "v" should be stripped from the C({ver}) place holder in C(template)
      - Does not affect release URL or download URL
    type: bool
    default: false
    aliases:
      - strip_v
  script:
    description:
      - If C(script) is not provided, the release will be marked as (un-)changed depending on the C(creates) option
      - If C(script) is provided, the script is run, and the installed release (if any) is extracted from its output
      - If the script fails to run or release cannot be extracted, the release is marked is changed
      - If the script runs successfully and a release is extracted, it is compared with release tag queried from github
      - If two release tags match, the release is marked as not changed, else as changed
    type: str
    aliases:
      - version_script
  regex:
    description:
      - A regular expression for extracting release tag from the C(script) output
    type: str
    default: "v[0-9][0-9a-z.-]+"
    aliases:
      - script_regex
  retries:
    description:
      - How many times should the module retry HTTP request if it fails
    type: int
    default: 3
'''

RETURN = r'''
url:
  description: A release URL or result of C(template) (if provided)
  returned: always
  type: str
  sample: https://github.com/github_user/package_name/releases/v1.0
msg:
  description: The HTTP message from the request
  returned: always
  type: str
  sample: OK (unknown bytes)
'''

EXAMPLES = r'''
- name: Find the latest release tag
    github_release:
      repo: ivault/vagrant-box-osx:latest
    register: result
  debug: msg={{ result.release }}

- name: Return URL of a downloadable release artifact
  github_release:
    repository: vagrant-box-osx
    owner: ivault
    release: v0.1.0
    template: "{download_url}/test_{ver}.zip"
  register: result
  debug: msg={{ result.url }}
'''

import os
import re
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import ensure_text
from ansible.modules.net_tools.basics.uri import uri


def main():
    module = AnsibleModule(
        argument_spec=dict(
            repo=dict(type='str', required=True, aliases=['repository']),
            user=dict(type='str', aliases=['owner']),
            release=dict(type='str', default='latest'),
            only_latest=dict(type='bool', default=True),
            stripv=dict(type='bool', default=False, aliases=['strip_v']),
            template=dict(type='str', aliases=['url_template']),
            shout=dict(type='str', default='latest', choices=['latest', 'always', 'never'], aliases=['shout_if']),
            creates=dict(type='path'),
            reinstall=dict(type='bool', default=False),
            script=dict(type='str', aliases=['version_script']),
            regex=dict(type='str', default='v[0-9][0-9a-z.-]+', aliases=['script_regex']),
            retries=dict(type='int', default=3),
        ),
        supports_check_mode=True,
    )

    repo = module.params['repo']
    user = module.params['user']
    release = module.params['release']

    if ':' in repo:
        parts = repo.split(':')
        if not release:
            release = parts[-1]
        repo = ':'.join(parts[:-1])

    if '/' in repo:
        parts = repo.split('/')
        if not user:
            user = parts[0]
        repo = '/'.join(parts[1:])

    url_repo = 'https://github.com/%s/%s' % (user, repo)
    tag_part = 'latest' if release == 'latest' else 'tag/%s' % release
    url_orig = '%s/releases/%s' % (url_repo, tag_part)

    creates = module.params['creates']
    reinstall = module.params['reinstall']
    if creates and os.path.exists(creates) and not reinstall:
        msg = "skipped, since '%s' exists" % creates
        module.exit_json(msg=msg, changed=False)

    ok_codes = [200]
    delay = 0.2
    retries = max(module.params['retries'], 1)
    only_latest = module.params['only_latest']

    for retry in range(retries):
        if only_latest and release != 'latest':
            status = ok_codes[0]
            msg = 'OK (skip)'
            res = dict(msg=msg, status=status)
            break

        module.params['src'] = None
        module.params['follow_redirects'] = 'safe'
        module.params['unix_socket'] = None

        res, _, _ = uri(module, url_orig,
                        method='HEAD',
                        headers={}, socket_timeout=30,
                        body=None, body_format='raw',
                        dest=None)
        status = int(res['status'])
        msg = res.get('msg', '')
        if status in ok_codes:
            break
        time.sleep(delay)
        delay = delay * 2

    url = res.get('url', '') or url_orig
    result = dict(status=status, url=url, retries=retry + 1)
    if url != url_orig:
        result['url_orig'] = url_orig

    if status not in ok_codes:
        result['msg'] = msg
        module.fail_json(**result)

    found = re.match(r'^https?://.+/releases/tag/([^/]+)$', result['url'])
    if not found:
        result['msg'] = 'cannot parse release url'
        module.fail_json(**result)

    ver = found.group(1)
    url_download = '%s/releases/download/%s' % (url_repo, ver)
    url_release = url  # FIXME

    stripv = module.params['stripv']
    if stripv and ver and ver[0] == 'v':
        ver = ver[1:]

    template = module.params['template']
    if template:
        url = template
        url = url.replace('{ver}', ver)
        url = url.replace('{repo_url}', url_repo)
        url = url.replace('{release_url}', url_release)
        url = url.replace('{download_url}', url_download)
        result['url_repo'] = url_repo
        result['url_release'] = url_release
        result['url_download'] = url_download
        result['url'] = url

    changed = True
    script = module.params['script']
    if script:
        regex = module.params['regex']
        installed = None
        changed = False
        if module.check_mode:
            msg = 'will not run script in check mode'
            changed = False
        else:
            rc, out, err = module.run_command(script,
                                              executable=None, use_unsafe_shell=True,
                                              encoding=None, data=None, binary_data=False)
            result['script_retval'] = rc
            result['script_stdout'] = out
            result['script_stderr'] = err
            if rc != 0:
                msg = "cannot run version script"
                out = ''
                changed = True
            else:
                found = re.findall(regex, ensure_text(out or '', errors='ignore'))
                if found:
                    installed = found[0]
                else:
                    msg = "installed version not found in script output"
            if stripv and installed and installed[0] == 'v':
                installed = installed[1:]

            if ver is not None and installed is not None:
                changed = ver != installed
                msg = "compared versions: github '%s' vs installed '%s'" % (ver, installed)
                if reinstall and not changed:
                    changed = True
                    msg += " (forced reinstall)"

        result['installed'] = installed

    result['release'] = ver
    if ver != release:
        result['release_orig'] = release

    shout_if = str(module.params['shout']).lower()
    shout_msg = '{} {} release: {}'.format(release, repo, ver)
    if msg.startswith('OK ') and ver != release:
        msg = shout_msg
    if shout_if == 'always' or release == 'latest' and shout_if == 'latest':
        module.warn(shout_msg)

    result['msg'] = msg
    result['changed'] = changed
    module.exit_json(**result)


if __name__ == '__main__':
    main()
