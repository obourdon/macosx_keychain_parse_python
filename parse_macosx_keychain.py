#!/usr/bin/env python

from datetime import datetime

import json
import os
import pdb
import re
import subprocess

from texttable import Texttable


attr_line_regexp1 = re.compile('^(0x[0-9a-fA-F]+) <([^>]+)>=(.*)$')
attr_line_regexp2 = re.compile('^"([^"]+)"<([^>]+)>=(.*)$')


def not_relevant(val: str) -> bool:
    # Potential matches in User keychain
    if val in [
        '<key>',
        'iMessage Signing Key',
        'iMessage Encryption Key',
        ]:
        return True
    if val.startswith('Apple ID '):
        return True
    if val.startswith('member: '):
        return True
    if val.startswith('0x'):
        return True
    # System keychain and other non handled/relevant cases
    if val in [
        'Imported Private Key',
        ]:
        return True
    if val.startswith('com.apple.'):
        return True
    print('ENTRY NOT HANDLED')
    #pdb.set_trace()
    return False



def parse_value(val: str) -> str:
    if val[0] == '"' and val[-1] == '"':
        return val[1:-1]
    return val



def parse_keychain_file_dump(file_path: str, origin: str) -> list[dict]:
    # Because security command does not return error code if file does not exist
    if not os.path.exists(os.path.expanduser(file_path)):
        raise Exception(f'File {file_path} does not exists')
    file_path = os.path.expanduser(file_path)
    if not os.access(file_path, os.R_OK):
        raise Exception(f'File {file_path} is not readable')
    # Execute the dump of the keychain file
    with os.popen("security dump-keychain " + file_path) as f:
        cur_line_nb = 0
        parsing_attributes = False
        # Initialize final result
        res_list = []
        # Initialize current object
        cur_obj = {}
        for l in f.readlines():
            cur_line_nb += 1
            # Skip keychain lines (start of a new entry)
            if l.startswith("keychain: "):
                if len(cur_obj):
                    res_list.append(cur_obj)
                # Reset parsing values due to new entry
                cur_obj = {}
                parsing_attributes = True
                continue
            # Remove trailing CR
            cl = l.strip("\n")
            #if cur_line_nb == 11427:
            #    pdb.set_trace()
            # For line starting with spaces, we should be parsing attributes
            if cl[0].isspace():
                # Standard second level attribute
                if parsing_attributes:
                    #print(f'GOT {cl.strip()}')
                    # Attributes format is one of
                    # 0x00000008 <blob>=......
                    # "acct"<blob>="Livebox-EF21"
                    m = attr_line_regexp1.match(cl.strip()) or attr_line_regexp2.match(cl.strip())
                    if m:
                        cur_obj['attributes'].append({'id': m[1], 'type': m[2], 'value': parse_value(m[3])})
                    else:
                        print(f'WARNING line {cur_line_nb}: bad attribute parsing: [{cl.strip()}]')
                else:
                    print(f'WARNING line {cur_line_nb}: not parsing attributes: {cl}')
            else:
                # Standard top level attribute
                items = cl.strip().split(': ')
                if len(items) != 2:
                    if items[0] == 'attributes:':
                        parsing_attributes = True
                        cur_obj['attributes'] = []
                    else:
                        print(f'WARNING line {cur_line_nb}: more than 2 elements found: {items}')
                else:
                    cur_obj[items[0]] = items[1]
                    cur_obj['origin'] = origin
        # In the end of parsing a dangling object (last entry) might require to be inserted
        if len(cur_obj):
            res_list.append(cur_obj)
    return res_list


def real_entry_account(entry: dict, key: str) -> str:
    name = list(filter(lambda x: (x['id'] == key), entry['attributes']))
    if len(name) > 0:
        return name[0].get('value', '<UNKNOWN>')
    return '<UNKNOWN>'


def row_item(e: dict, k: str) -> str:
    v = e.get(k, '')
    if v == '<NULL>':
        v = ''
    return v


'''
security list-keychains # (removed dummy entries)
    "/Users/olivierbourdon/Library/Keychains/login.keychain-db"
    "/Library/Keychains/System.keychain"

for ICloud, cf https://apple.stackexchange.com/questions/238296/dump-icloud-keychain-in-terminal
iCloud Keychain is stored on disk in a different format than a traditional keychain ref1, ref2. It's located at ~/Library/Keychains/ in a folder named as a long UUID. You can see the modified timestamp change on the contents of that folder as you change something in your iCloud keychain.

The UUID is your system's hardware platform UUID (IOPlatformUUID), which you can read using the following shell command (Ref): ioreg -d2 -c IOPlatformExpertDevice | awk -F\" "/IOPlatformUUID/{print \\$(NF-1)}"

cf https://gist.github.com/rmondello/b933231b1fcc83a7db0b
'''


try:
    # May be do same thing with iCloud but see comments above
    resl = parse_keychain_file_dump("~/Library/Keychains/login.keychain-db", "User")
    # Add System keychains (mainly for AirPort networks)
    resl.extend(
        parse_keychain_file_dump("/Library/Keychains/System.keychain", "System")
    )
    print(f'Found {len(resl)} entries')
    discarded = 0
    final_res = []
    for i in resl:
        cur_obj = i['attributes'][1]
        if cur_obj['id'] == '0x00000001' and cur_obj['type'] == 'blob' and not_relevant(cur_obj['value']):
            discarded += 1
            continue
        details = {}
        baba = False
        for d in list(filter(lambda x: (x['id'] in ['acct', 'cdat', 'mdat', 'desc', 'port', 'ptcl', 'svce', 'srvr']), i['attributes'])):
            if d['id'] == 'acct':
                details['account'] = d['value']
            elif d['id'] == 'ptcl':
                v = d['value']
                # Coding is on 4 chars -> htps becomes https
                if v == 'htps':
                    v = 'https'
                # For 3 chars code, remove trailing space
                details['protocol'] = v.strip()
            elif d['id'] == 'port':
                v = int(d['value'].split()[0], 0)
                if v != 0:
                    details['port'] = v
            elif d['id'] == 'desc':
                details['desc'] = d['value']
                # For some reason on some systems, the output is a mix of French and English :-(
                if d['value'].endswith('seau AirPort"'):
                    details['desc'] = 'AirPort network password'
                elif d['value'] == 'Mot de passe de formulaire Web' or d['value'] == 'Mot de passe de formulaire web':
                    details['desc'] = 'Web form password'
                elif 'Mot de passe de r' in d['value'] and d['value'].endswith('seau"'):
                    details['desc'] = 'Network Password'
                elif d['value'] == 'Encrypted Volume Password':
                    # Need to store 1st attribute -> see for all
                    details['tokeep'] = True
                    # Need to switch value for proper information on encrypted volumes
                    details['type'] = 'encrypted'
                    details['srvr'] = details['account']
                    details['account'] = real_entry_account(i, '0x00000007')
            elif d['id'] == 'cdat' or d['id'] == 'mdat':
                details[d['id']] = datetime.strftime(datetime.strptime(d['value'].split()[-1].replace('"', '').replace('Z\\000',''), '%Y%m%d%H%M%S'), '%Y-%m-%d %H:%M:%S')
            elif d['id'] == 'svce':
                if 'AirPort' in d['value']:
                    details['type'] = 'airport'
                    details['tokeep'] = True
                if 'com.apple.network.wlan.ssid' in d['value']:
                    details['type'] = 'wlan'
                    details['tokeep'] = True
            elif d['id'] == 'srvr':
                details['srvr'] = d['value']
                details['type'] = 'web'
                details['tokeep'] = True
        if details.get('tokeep', False):
            details.pop('tokeep')
            details['origin'] = i['origin']
            if details['account'] == 'AirPort' and details['type'] == 'wlan':
                details['account'] = real_entry_account(i, '0x00000007')
            if details['desc'] == '<NULL>':
                details['desc'] = 'Internet password'
                extra = real_entry_account(i, 'sdmn')
                if len(extra) > 0 and extra != '<NULL>':
                    details['extra'] = extra
                extra = real_entry_account(i, 'path')
                if len(extra) > 0 and extra != '<NULL>':
                    details['extra'] = f'{details.get('extra', '')} {extra}'
                if len(details.get('extra', '')) > 0:
                    details['extra'] = details['extra'].strip()    
            final_res.append(details)
            continue
        discarded += 1
        if cur_obj['id'] in ['cenc']:
            continue
        #print(cur_line_nb, cur_obj, details)
        #print(json.dumps(i, indent=2))
        #pdb.set_trace()
    print(f'Discarded {discarded} unrelevant entries')
    print(f'Kept {len(final_res)} entries')
#    print(json.dumps(final_res, indent=2))
    # https://github.com/foutaise/texttable/
    table = Texttable(max_width=140)
    #table.set_cols_align(["l", "r", "c"])
    #table.set_cols_valign(["t", "m", "b"])
    # Must be text most of the time to avoid numeric string to
    # be printed as floats
    table.set_cols_dtype(['t', 't', 't', 't', 'a', 'a', 't', 'i', 't', 't'])
    table.add_rows([["Keychain", "Name", "Server", "Kind", "Created", "Modified", 'Protocol', "Port", "Description", "Extra"]])
    for e in final_res:
        #if len(e) < 6 or len(e) > 9:
        #    print(len(e), e)
        table.add_row([
                row_item(e, 'origin'),
                row_item(e, 'account'),
                row_item(e, 'srvr'),
                row_item(e, 'type'),
                row_item(e, 'cdat'),
                row_item(e, 'mdat'),
                row_item(e, 'protocol'),
                row_item(e, 'port'),
                row_item(e, 'desc'),
                row_item(e, 'extra'),
                ])
    print(table.draw())
except Exception as e:
    print(f'Got exception running Keychain dump command {e}')
