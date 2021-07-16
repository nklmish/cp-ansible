#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes, to_native, to_text

import os
import re
import tempfile
import base64

def to_dict(b_lines):
    entries = dict()
    for line in b_lines:
        line = line.strip()
        if '=' not in line: continue
        k,v = line.split('=', 1)
        entries[k.strip()] = v.strip()
    return entries

def current_time():
    import datetime
    return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f000 UTC')

def write_changes(module, b_lines, dest):

    tmpfd, tmpfile = tempfile.mkstemp(dir=module.tmpdir)
    with os.fdopen(tmpfd, 'wb') as f:
        f.writelines(b_lines)

    module.atomic_move(tmpfile,
                       to_native(os.path.realpath(to_bytes(dest, errors='surrogate_or_strict')), errors='surrogate_or_strict'),
                       unsafe_writes=True)

def check_file_attrs(module, changed, message, diff):
    file_args = module.load_file_common_arguments(module.params)
    if module.set_fs_attributes_if_different(file_args, False, diff=diff):
        if changed:
            message += " and "
        changed = True
        message += "ownership, perms or SE linux context changed"
    return message, changed

def encrypt(module, data, key, iv):

    (rc, out, err) = module.run_command(
        ['openssl', 'enc', '-aes-256-cbc', '-e', '-K', key.encode('hex'), '-iv', iv.encode('hex')], 
        check_rc=False,
        binary_data=True,
        encoding=None,
        data=data)

    if rc!=0:
        raise OpenSSLInvocationFailed

    return out

def decrypt(module, data, key, iv):

    (rc, out, err) = module.run_command(
        ['openssl', 'enc', '-aes-256-cbc', '-d', '-K', key.encode('hex'), '-iv', iv.encode('hex')], 
        check_rc=False,
        binary_data=True,
        encoding=None,
        data=data)

    if rc!=0:
        raise OpenSSLInvocationFailed

    return out

class OpenSSLInvocationFailed(Exception):
    pass

def encrypt_entry(module, decrypted, key):
    iv = os.urandom(16)
    data = encrypt(module, decrypted, key, iv)
    return 'ENC[AES/CBC/PKCS5Padding,data:%s,iv:%s,type:str]' % (base64.b64encode(data), base64.b64encode(iv))

def decrypt_entry(module, encrypted, key):
    match = re.match('^ENC\\[AES/CBC/PKCS5Padding,data:(.*),iv:(.*),type:str\\]$', encrypted)
    if not match:
        module.fail_json(msg='Expected encrypted entry, got: %s' % encrypted)
    data, iv = match.groups()
    return decrypt(module, base64.b64decode(data), key, base64.b64decode(iv))


def present(module, secret_file, master_key, master_key_envvar, master_key_length, entry, value):

    diff = {'before': '',
            'after': '',
            'before_header': '%s (content)' % secret_file,
            'after_header': '%s (content)' % secret_file}

    b_dest = to_bytes(secret_file, errors='surrogate_or_strict')
    if not os.path.exists(b_dest):
        b_destpath = os.path.dirname(b_dest)
        if b_destpath and not os.path.exists(b_destpath) and not module.check_mode:
            try:
                os.makedirs(b_destpath)
            except Exception as e:
                module.fail_json(msg='Error creating %s (%s)' % (to_text(b_destpath), to_text(e)))
        b_lines = []
    else:
        with open(b_dest, 'rb') as f:
            b_lines = f.readlines()

    b_linesep = to_bytes(os.linesep, errors='surrogate_or_strict')
    changes = list()

    if module._diff:
        diff['before'] = to_native(b''.join(b_lines))

    entries = to_dict(b_lines)

    if '_metadata.master_key.0.salt' not in entries:
        changes.append('added master key salt')
        b_lines.append('_metadata.master_key.0.salt = %s%s' % (base64.b64encode(os.urandom(32)), b_linesep))
    if '_metadata.symmetric_key.0.created_at' not in entries:
        changes.append('added symmetric key created at')
        b_lines.append('_metadata.symmetric_key.0.created_at = %s%s' % (current_time(), b_linesep))
    if '_metadata.symmetric_key.0.envvar' not in entries:
        changes.append('added symmetric key envvar')
        b_lines.append('_metadata.symmetric_key.0.envvar = %s%s' % (master_key_envvar, b_linesep))
    if '_metadata.symmetric_key.0.length' not in entries:
        changes.append('added symmetric key length')
        b_lines.append('_metadata.symmetric_key.0.length = %d%s' % (master_key_length, b_linesep))
    if '_metadata.symmetric_key.0.iterations' not in entries:
        changes.append('added symmetric key iterations')
        b_lines.append('_metadata.symmetric_key.0.iterations = %d%s' % (1000, b_linesep))
    if '_metadata.symmetric_key.0.salt' not in entries:
        changes.append('added symmetric key salt')
        b_lines.append('_metadata.symmetric_key.0.salt = %s%s' % (base64.b64encode(os.urandom(32)), b_linesep))

    # kek - key encryption key
    # dek - data encryption key
    kek = base64.b64decode(master_key)
    if '_metadata.symmetric_key.0.enc' not in entries:
        changes.append('added symmetric key')
        dek = os.urandom(32)
        b_lines.append('_metadata.symmetric_key.0.enc = %s%s' % (encrypt_entry(module, base64.b64encode(dek), kek), b_linesep))
    else:
        dek = base64.b64decode(decrypt_entry(module, entries['_metadata.symmetric_key.0.enc'], kek))

    if entry not in entries:
        changes.append('added entry %s' % entry)
        b_lines.append('%s = %s%s' % (entry, encrypt_entry(module, value, dek), b_linesep))
    elif value != decrypt_entry(module, entries[entry], dek):
        new_b_lines = list()
        for line in b_lines:
            if '=' not in line: continue
            k,v = line.strip().split('=', 1)
            k = k.strip()
            v = v.strip()
            if k == entry:
                changes.append('replaced entry %s' % k)
                new_b_lines.append('%s = %s%s' % (entry, encrypt_entry(module, value, dek), b_linesep))
            else:
                new_b_lines.append(line)
        b_lines = new_b_lines


    if module._diff:
        diff['after'] = to_native(b''.join(b_lines))

    if changes and not module.check_mode:
        write_changes(module, b_lines, secret_file)

    changed = len(changes)!=0
    msg = ' and '.join(changes)

    attr_diff = {}
    msg, changed = check_file_attrs(module, changed, msg, attr_diff)

    attr_diff['before_header'] = '%s (file attributes)' % secret_file
    attr_diff['after_header'] = '%s (file attributes)' % secret_file

    difflist = [diff, attr_diff]

    module.exit_json(changed=changed, msg=msg, diff=difflist)
    
def absent(module, secret_file, entry):

    diff = {'before': '',
            'after': '',
            'before_header': '%s (content)' % secret_file,
            'after_header': '%s (content)' % secret_file}

    b_dest = to_bytes(secret_file, errors='surrogate_or_strict')
    if not os.path.exists(b_dest):
        b_destpath = os.path.dirname(b_dest)
        if b_destpath and not os.path.exists(b_destpath) and not module.check_mode:
            try:
                os.makedirs(b_destpath)
            except Exception as e:
                module.fail_json(msg='Error creating %s (%s)' % (to_text(b_destpath), to_text(e)))
        old_lines = []
    else:
        with open(b_dest, 'rb') as f:
            b_lines = f.readlines()

    b_linesep = to_bytes(os.linesep, errors='surrogate_or_strict')
    changes = list()

    if module._diff:
        diff['before'] = to_native(b''.join(b_lines))

    new_b_lines = list()
    for line in b_lines:
        if '=' not in line: continue
        k,v = line.strip().split('=', 1)
        k = k.strip()
        v = v.strip()
        if k == entry:
            changes.append('removed entry %s' % k)
        else:
            new_b_lines.append(line)
    b_lines = new_b_lines

    if module._diff:
        diff['after'] = to_native(b''.join(b_lines))

    if changes and not module.check_mode:
        write_changes(module, b_lines, secret_file)        

    changed = len(changes)!=0
    msg = ' and '.join(changes)

    attr_diff = {}
    msg, changed = check_file_attrs(module, changed, msg, attr_diff)

    attr_diff['before_header'] = '%s (file attributes)' % secret_file
    attr_diff['after_header'] = '%s (file attributes)' % secret_file

    difflist = [diff, attr_diff]

    module.exit_json(changed=changed, msg=msg, diff=difflist)

def rotated(module, secret_file, master_key, master_key_old, master_key_envvar, master_key_length, entry):

    diff = {'before': '',
            'after': '',
            'before_header': '%s (content)' % secret_file,
            'after_header': '%s (content)' % secret_file}

    b_dest = to_bytes(secret_file, errors='surrogate_or_strict')
    if not os.path.exists(b_dest):
        b_destpath = os.path.dirname(b_dest)
        if b_destpath and not os.path.exists(b_destpath) and not module.check_mode:
            try:
                os.makedirs(b_destpath)
            except Exception as e:
                module.fail_json(msg='Error creating %s (%s)' % (to_text(b_destpath), to_text(e)))
        b_lines = []
    else:
        with open(b_dest, 'rb') as f:
            b_lines = f.readlines()

    b_linesep = to_bytes(os.linesep, errors='surrogate_or_strict')
    changes = list()

    if module._diff:
        diff['before'] = to_native(b''.join(b_lines))

    entries = to_dict(b_lines)
    if '_metadata.master_key.0.salt' not in entries:
        changes.append('added master key salt')
        b_lines.append('_metadata.master_key.0.salt = %s%s' % (base64.b64encode(os.urandom(32)), b_linesep))
    if '_metadata.symmetric_key.0.created_at' not in entries:
        changes.append('added symmetric key created at')
        b_lines.append('_metadata.symmetric_key.0.created_at = %s%s' % (current_time(), b_linesep))
    if '_metadata.symmetric_key.0.envvar' not in entries:
        changes.append('added symmetric key envvar')
        b_lines.append('_metadata.symmetric_key.0.envvar = %s%s' % (master_key_envvar, b_linesep))
    if '_metadata.symmetric_key.0.length' not in entries:
        changes.append('added symmetric key length')
        b_lines.append('_metadata.symmetric_key.0.length = %d%s' % (master_key_length, b_linesep))
    if '_metadata.symmetric_key.0.iterations' not in entries:
        changes.append('added symmetric key iterations')
        b_lines.append('_metadata.symmetric_key.0.iterations = %d%s' % (1000, b_linesep))
    if '_metadata.symmetric_key.0.salt' not in entries:
        changes.append('added symmetric key salt')
        b_lines.append('_metadata.symmetric_key.0.salt = %s%s' % (base64.b64encode(os.urandom(32)), b_linesep))

    # kek - key encryption key
    # dek - data encryption key
    kek = base64.b64decode(master_key)
    if '_metadata.symmetric_key.0.enc' not in entries:
        changes.append('added symmetric key')
        old_dek = os.urandom(32)
        new_dek = old_dek
        b_lines.append('_metadata.symmetric_key.0.enc = %s%s' % (encrypt_entry(module, base64.b64encode(new_dek), kek), b_linesep))
    elif entry:
        old_dek = base64.b64decode(decrypt_entry(module, entries['_metadata.symmetric_key.0.enc'], kek))
        new_dek = old_dek
    else:
        changes.append('rotated symmetric key')
        try:
            old_dek = base64.b64decode(decrypt_entry(module, entries['_metadata.symmetric_key.0.enc'], base64.b64decode(master_key_old)))
        except OpenSSLInvocationFailed:
            old_dek = base64.b64decode(decrypt_entry(module, entries['_metadata.symmetric_key.0.enc'], base64.b64decode(master_key)))
        new_dek = os.urandom(32)

    new_b_lines = list()
    for line in b_lines:
        if '=' not in line: continue
        k,v = line.strip().split('=', 1)
        k = k.strip()
        v = v.strip()
        if k == '_metadata.symmetric_key.0.enc' and old_dek!=new_dek:
            new_b_lines.append('_metadata.symmetric_key.0.enc = %s%s' % (encrypt_entry(module, base64.b64encode(new_dek), kek), b_linesep))        
        elif k.startswith('_metadata.'):
            new_b_lines.append(line)
        elif entry is None or k == entry:
            changes.append('rotated entry %s' % k)
            value = decrypt_entry(module, v, old_dek)
            new_b_lines.append('%s = %s%s' % (k, encrypt_entry(module, value, new_dek), b_linesep))
        else:
            new_b_lines.append(line)
    b_lines = new_b_lines

    if module._diff:
        diff['after'] = to_native(b''.join(b_lines))

    if changes and not module.check_mode:
        write_changes(module, b_lines, secret_file)

    changed = len(changes)!=0
    msg = ' and '.join(changes)

    attr_diff = {}
    msg, changed = check_file_attrs(module, changed, msg, attr_diff)

    attr_diff['before_header'] = '%s (file attributes)' % secret_file
    attr_diff['after_header'] = '%s (file attributes)' % secret_file

    difflist = [diff, attr_diff]

    module.exit_json(changed=changed, msg=msg, diff=difflist)


def main():

    argument_spec = dict(
        path              = dict(type='path', required=True, aliases=['secret_file']),
        master_key        = dict(type='str',  required=True, no_log=True),
        master_key_old    = dict(type='str',  required=False, no_log=True),
        master_key_envvar = dict(type='str',  required=False, default='CONFLUENT_SECURITY_MASTER_KEY'),
        master_key_length = dict(type='int',  required=False, default=32),
        entry             = dict(type='str',  required=False, default=None),
        value             = dict(type='str',  required=False, no_log=True, default=None),
        state             = dict(type='str',  required=False, default='present', choices=['present', 'absent', 'rotated']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        add_file_common_args=True,
        supports_check_mode=True,        
    )

    p = module.params

    secret_file       = p.get('path')
    master_key        = p.get('master_key')
    master_key_old    = p.get('master_key_old')
    master_key_envvar = p.get('master_key_envvar')
    master_key_length = p.get('master_key_length')
    entry             = p.get('entry')
    value             = p.get('value')
    state             = p.get('state')

    if state == 'present':

        if entry is None:
            module.fail_json(msg='entry is required with state=present')
        if value is None:
            module.fail_json(msg='value is required with state=present')
        if master_key_old is not None:
            module.fail_json(msg='master_key_old is used with state=rotated only')

        present(module, secret_file, master_key, master_key_envvar, master_key_length, entry, value)

    elif state == 'absent':

        if entry is None:
            module.fail_json(msg='entry is required with state=absent')
        if value is not None:
            module.fail_json(msg='value is not expected with state=absent')
        if master_key_old is not None:
            module.fail_json(msg='master_key_old is used with state=rotated only')

        absent(module, secret_file, entry)

    elif state == 'rotated':

        if value is not None:
            module.fail_json(msg='value is not expected with state=rotated')
        if master_key_old is not None and entry is not None:
            module.fail_json(msg='master_key_old cannot be used together with entry')

        if master_key_old is None:
            master_key_old = master_key

        rotated(module, secret_file, master_key, master_key_old, master_key_envvar, master_key_length, entry)

    else:

        module.fail_json(msg="Invalid target state: %s" % state)

if __name__ == '__main__':
    main()
