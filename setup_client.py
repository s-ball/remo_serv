#  Copyright (c) 2020 SBA - MIT License

from setuptools import setup
from warnings import warn


import os.path
import re
import subprocess

import sys

sys.path.append('.')

pkg = 'client'
wd = os.path.abspath(os.path.dirname(__file__))
_version = None


def get_version() -> str:
    global _version
    if _version is not None:
        return _version
    """ extract version number """
    _version = '0.0.0'  # fallback value should never be used
    try:  # first from git using setuptools_scm
        from setuptools_scm import get_version as scm_version
        _version = scm_version(write_to=os.path.join(wd, pkg, 'version.py'))
    except (ImportError, LookupError):
        try:  # else from a previous version.py
            with open(os.path.join(wd, pkg, 'version.py')) as fd:
                for line in fd:
                    if line.startswith('version'):
                        _version = line.split("'")[1]
        except OSError:
            warn('Need either git+setuptools-scm or version.py file')
    return _version


def get_commit() -> str:
    try:
        p = subprocess.run('git show --format=%H -s', capture_output=True,
                           check=True, shell=True, encoding='Latin1')
    except (OSError, subprocess.CalledProcessError):
        return ''
    return p.stdout.strip()


def get_long_desc() -> str:
    """ read long description and adjust master with version for badges or links
    only for release versions (x.y.z)
    """
    get_version()
    release = re.compile(r'(\d+\.){0,2}\d+$')
    with open(os.path.join(wd, 'README.md')) as fd:
        if _version == '0.0.0' or not release.match(_version):
            _long_description = fd.read()
        else:
            lines = fd.readlines()
            for i, line in enumerate(lines):
                if not line.startswith('['):
                    break
                if 'travis' in line:
                    lines[i] = line.replace('master', _version)
                elif 'codecov' in line:
                    commit = get_commit()
                    if commit != '':
                        lines[i] = line.replace('branch/master',
                                                'commit/' + commit)
            _long_description = ''.join(lines)
    return _long_description


if __name__ == '__main__':
    setup(
        version=get_version(),
        long_description=get_long_desc(),
        long_description_content_type='text/markdown',
        packages = ['client', 'tools'],
        name='client',
    )
