#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
import logging

# extra modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'Python Module Example',
    'description': '''
        Python communication with msfconsole.
    ''',
    'authors': [
        'Jacob Robles'
    ],
    'date': '2018-03-22',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://blog.rapid7.com/2017/12/28/regifting-python-in-metasploit/'},
        {'type': 'aka', 'ref': 'Coldstone'}
    ],
    'type': 'single_scanner',
    'options': {
        'targeturi': {'type': 'string', 'description': 'The base path', 'required': True, 'default': '/'},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None}
    }
}


def run(args):
    module.LogHandler.setup(msg_prefix=f"{args['rhost']} - ")
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    # Your code here
    try:
        r = requests.get(f"https://{args['rhost']}/{args['targeturi']}", verify=False)
    except requests.exceptions.RequestException as e:
        logging.error(f'{e}')
        return

    logging.info(f'{r.text[:50]}...')


if __name__ == '__main__':
    module.run(metadata, run)
