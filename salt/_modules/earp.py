# -*- coding: utf-8 -*-
'''
:maintainer: Dan McTeer (mcteer@adobe.com)
:maturity: new
:requires: none
:platform: all
'''

from __future__ import absolute_import

try:
    import json, ldap, logging, os, pwd, re, salt, zlib
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
except ImportError, imperr:
    err_list = str(imperr).split(' ')
    print 'Unable to import module: ' + err_list[3]

LOG = logging.getLogger(__name__)


## PUBLIC FUNCTIONS ##

def bundle_status(*args):
    '''
    View the Contents of Target Encrypted Bundle on Target Minion
    '''

    errors = {}
    account_dict = {}
    bundle_dict = {}
    bundle_list = _getBundles()

    ## Check for Supported OS ##
    if __salt__['grains.get']('os') == 'Windows':
        return 'Unsupported Operating System'

    ## Fetch Bundle Info ##
    if isinstance(bundle_list, list):
        if not bundle_list:
            return 'No Encrypted Bundles Present'
        else:
            for bundle in bundle_list:
                bundle_dict.update({bundle: _checkBundle(bundle)})
    else:
        return 'No Encrypted Bundles Present'

    ## Fetch Permitted Accounts/Keys ##
    _refreshPillar()
    if __salt__['pillar.get']('cmdb:secrets'):
        for key, info in __salt__['pillar.get']('cmdb:secrets').iteritems():
            if 'users' not in info:
                pass
            else:
                for uname in info['users']:
                    if not account_dict:
                        account_dict.update({uname: [key]})
                    if uname in account_dict:
                        if key in account_dict[uname]:
                            pass
                        else:
                            account_dict[uname].append(key)
                    else:
                        account_dict.update({uname: [key]})

    if __salt__['pillar.get']('bundle_users'):
        account_dict.update(__salt__['pillar.get']('bundle_users'))
                
    if not account_dict:
        return 'No Secrets Permitted'

    ## Check Secrets Against Secret Store ##
    for bundle, info in bundle_dict.iteritems():
        account = _getUser(bundle.replace('.asc', ''))
        if account in account_dict:
            for user, secret in info.iteritems():
                if user not in account_dict[account]:
                    if not errors:
                        errors.update({bundle: {user: 'Unauthorized Secret'}})
                    elif bundle not in errors:
                        errors.update({bundle: {user: 'Unauthorized Secret'}})
                    else:
                        errors[bundle].update({user: 'Unauthorized Secret'})
                elif 'password' not in secret:
                    pass
                elif secret['password'].strip() == __salt__['pillar.get'](user + ':password').strip():
                    pass
                elif secret['password'].strip() == __salt__['pillar.get']('cmdb:secrets:' + user + ':password').strip():
                    pass
                else:
                    if not errors:
                        errors.update({bundle: {user: 'Secret Mismatch'}})
                    elif bundle not in errors:
                        errors.update({bundle: {user: 'Secret Mismatch'}})
                    else:
                        errors[bundle].update({user: 'Secret Mismatch'})
        else:
            if not errors:
                errors.update({bundle: 'User Not Authorized'})
            elif bundle not in errors:
                errors.update({bundle: 'User Not Authorized'})
            else:
                errors[bundle].update('User Not Authorized')

    if not errors:
        result = True
    elif 'verbose' in args:
        result = errors
    else:
        result = False

    return result


def idm_status(*args):
    '''
    Check status of SSSD client
    '''

    error = ''

    if __salt__['config.get']('os') == 'CentOS':
        if __salt__['service.status']('sssd') == True:
            if _checkSSSDAgent('') == True:
                pass
            else:
                error = _checkSSSDAgent('')
        elif __salt__['service.available']('sssd') == True:
            if 'sssd' in __salt__['pillar.items']():
                if _checkSSSDPillar() == True:
                    pass
                else:
                    error = _checkSSSDPillar()
            else:
                error = 'SSSD Service Not Running'
        else:
            error = 'SSSD Unavailable'

    elif __salt__['config.get']('os') == 'Windows':
        if __salt__['grains.get']('windowsdomain') == 'WORKGROUP':
            pass
        else:
            error = 'Windows Domain Misconfigured'

    if not error:
        result = True
    elif 'verbose' in args:
        result = error
    else:
        result = False

    return result


def secret_status(*args):
    '''
    Check Secrets for Local Accounts
    '''

    errors = {}
    secret_dict = __salt__['pillar.items']()


    _refreshPillar()
    if __salt__['config.get']('os') == 'CentOS':
        for user, passwd in _getShadow().iteritems():
            if 'cmdb' in secret_dict:
                if 'secrets' in secret_dict['cmdb']:
                    if user + '_hash' in secret_dict['cmdb']['secrets']:
                        if 'password' in secret_dict['cmdb']['secrets'][user + '_hash']:
                            temp_pass = secret_dict['cmdb']['secrets'][user + '_hash']['password']
                        else:
                            errors.update({user: 'No Password for User'})
                    elif user in secret_dict['cmdb']['secrets']:
                        if 'password' in secret_dict['cmdb']['secrets'][user]:
                            temp_pass = secret_dict['cmdb']['secrets'][user]['password']
                        else:
                            errors.update({user: 'No Password for User'})
                    elif user + '_hash' in secret_dict:
                        if 'password' in secret_dict[user + '_hash']:
                            temp_pass = secret_dict[user + '_hash']['password']
                        else:
                            errors.update({user: 'No Password for User'})
                    elif user in secret_dict:
                        if 'password' in secret_dict[user]:
                            temp_pass = secret_dict[user]['password']
                        else:
                            errors.update({user: 'No Password for User'})
                    else:
                        errors.update({user: 'User Not Authorized'})
                else:
                    if user + '_hash' in secret_dict:
                        if 'password' in secret_dict[user + '_hash']:
                            temp_pass = secret_dict[user + '_hash']['password']
                        else:
                            errors.update({user: 'No Password for User'})
                    elif user in secret_dict:
                        if 'password' in secret_dict[user]:
                            temp_pass = secret_dict[user]['password']
                        else:
                            errors.update({user: 'No Password for User'})
                    else:
                        errors.update({user: 'User Not Authorized'})
            else:
                if user + '_hash' in secret_dict:
                    if 'password' in secret_dict[user + '_hash']:
                        temp_pass = secret_dict[user + '_hash']['password']
                    else:
                        errors.update({user: 'No Password for User'})
                elif user in secret_dict:
                    if 'password' in secret_dict[user]:
                        temp_pass = secret_dict[user]['password']
                    else:
                        errors.update({user: 'No Password for User'})
                else:
                    errors.update({user: 'User Not Authorized'})

            if passwd.strip() == temp_pass.strip():
                pass
            else:
                if not errors:
                    errors.update({user: 'Secret Mismatch'})
                elif user not in errors:
                    errors.update({user: 'Secret Mismatch'})

    elif __salt__['config.get']('os') == 'Windows':
        return 'Unsupported Operating System'

    if not errors:
        result = True
    elif 'verbose' in args:
        result = errors
    else:
        result = False

    return result



## PRIVATE FUNCTIONS ##

def _aesDecrypt(bundle):
    '''
    Decrypt Target Encrypted Bundle
    '''

    # Get Decryption Keys #
    key_dict = _getKeyPair()
    aes_key = str(key_dict['aes_key']).rstrip('\n')
    hmac_key = str(key_dict['hmac_key']).rstrip('\n')

    # Get Cipher Text #
    with open(bundle, 'r') as fh_:
        cipher_text = fh_.read()

    # Decrypt Cipher Text #
    header = cipher_text[:32]
    data = cipher_text[32:]
    aes_tag = data[:AES.block_size]
    aes_body = data[AES.block_size:]
    aes = AES.new(aes_key, AES.MODE_CFB, aes_tag)
    plain_text = aes.decrypt(aes_body)

    # Compare HMAC for Data Integrity #
    hmac_tag = HMAC.new(hmac_key, data, SHA256).digest()
    hmac_check = 0

    for char1, char2 in zip(aes_tag, hmac_tag):
        hmac_check != ord(char1) ^ ord(char2)

    # Decompress Vault #
    if hmac_check == 0:
        plain_text = json.loads(str(zlib.decompress(plain_text).decode('utf-8')))
        return json.dumps(plain_text, sort_keys=True, indent=2, separators=(',', ':'))
    else:
        return 'Digest mismatch - vault integrity compromised!'


def _bindLDAP(ldap_host):
    '''
    Bind to LDAP to facilitate queries
    '''

    try:
        ldap_con = ldap.initialize('ldaps://ldap.dmz.ut1.adobe.net:636')
        ldap_con.protocol_version = ldap.VERSION3
        return ldap_con
    except ldap.LDAPError, ldap_err:
        return ldap_err


def _checkBundle(bundle):
    '''
    Check Contents of Encrypted Bundle Against Secret Store
    '''

    if __salt__['grains.get']('os') == 'Windows':
        return json.loads(_aesDecrypt('C:\Users\charlie' + bundle))
    else:
        return json.loads(_aesDecrypt('/home/charlie/' + bundle))


def _checkSSSDAgent(check_type):
    '''
    Check SSSD Agent Status/Configuration
    '''

    error = ''
    ldap_hosts = []

    if __salt__['file.contains']('/etc/sssd/sssd.conf', 'ldap_uri') == True:
        output = __salt__['file.grep']('/etc/sssd/sssd.conf', 'ldap_uri')['stdout']
        ldap_list = output.split('ldap_uri = ')[1].split()
    else:
        error = 'No LDAP Hosts Configured'

    if check_type == 'groups':
        if not error:
            return ldap_list
        else:
            return error
    else:
        for item in ldap_list:
            host = re.search(r"(^.*)://(.*):(\d*$)", item.strip(','))
            ldap_hosts.append(host.group(2))

        if not ldap_hosts:
            error = 'No LDAP Hosts Configured'
        else:
            for host in ldap_hosts:
                if 'adobe' or 'localhost' in host:
                    continue
                else:
                    error = 'Unidentified LDAP Host'

    if not error:
        result = True
    else:
        result = error

    return result


def _checkSSSDPillar():
    '''
    Check for Presence/Use of SSSD Pillar
    '''

    error = {}
    user_dict = __salt__['pillar.get']('sssd')
    key_dict = {}

    ## Check /etc/shadow for Hashes ##
    shadow_dict = _getShadow()

    ## Check for SSH Keys ##
    for roots, dirs, files in os.walk('/home'):
        if 'authorized_keys' in files:
            head, tail = os.path.split(roots.replace('/.ssh', ''))
            with open(roots + '/authorized_keys', 'r') as fh_:
                for line in fh_:
                    if not key_dict:
                        key_dict.update({tail: {'keys': [line.strip()]}})
                    elif tail not in key_dict:
                        key_dict.update({tail: {'keys': [line.strip()]}})
                    elif line.strip() not in key_dict[tail]['keys']:
                        key_dict[tail]['keys'].append(line.strip())

    if os.path.isfile('/root/.ssh/authorized_keys') == True:
        with open('/root/.ssh/authorized_keys', 'r') as fh_:
            for line in fh_:
                if not key_dict:
                    key_dict.update({'root': {'keys': [line.strip()]}})
                elif 'root' not in key_dict:
                    key_dict.update({'root': {'keys': [line.strip()]}})
                elif line.strip() not in key_dict['root']['keys']:
                    key_dict['root']['keys'].append(line.strip())

    ## Check Local SSH Keys Against LDAP ##
    if not user_dict or not user_dict['users']:
        error = 'LDAP Data Unavailable'
    else:
        for user, keys in key_dict.iteritems():
            if len(keys['keys']) > 1:
                error.update({user: 'Multiple SSH Keys'})
            elif user == 'root':
                pass
            else:
                if user not in user_dict['users']:
                    error.update({user: 'User Not Authorized'})
                elif 'ssh_key' not in user_dict['users'][user]:
                    error.update({user: 'No SSH Key Available'})
                elif keys['keys'][0].strip() == user_dict['users'][user]['ssh_key'].strip():
                    pass 
                else:
                    error.update({user: 'Invalid SSH Key'})

    ## Check for Local Passwords ##
    for user, keys in key_dict.iteritems():
        if user in shadow_dict:
            if user == 'root':
                pass
            else:
                error.update({user: 'Local Password Set'})

    if not error:
        result = True
    else:
        result = error

    return result


def _getBundles(*args):
    '''
    List Encrypted Bundles
    '''

    bundles = []

    if __salt__['grains.get']('os') == 'Windows':
        if __salt__['file.directory_exists']('C:\Users\charlie') == True:
            dir_list = __salt__['file.readdir']('C:\Users\charlie')
        else:
            return 'No Secrets User Directory'
    else:
        if __salt__['file.directory_exists']('/home/charlie') == True:
            dir_list = __salt__['file.readdir']('/home/charlie')
        else:
            return 'No Secrets User Directory'

    if isinstance(dir_list, list):
        for item in dir_list:
            if '.asc' in item:
                bundles.append(item)
    elif not bundles:
        return 'No Encrypted Bundles'
    else:
        return 'No Encrypted Bundles'

    return bundles


def _getKeyPair():
    '''
    Get AES/HMAC Keys from Minion
    '''

    key_dict = {'aes_key': '', 'hmac_key': ''}

    if __salt__['grains.get']('os') == 'Windows':
        key_dict['aes_key'] = __salt__['cmd.run']('type C:\Users\Administrator\.aes.key')
        key_dict['hmac_key'] = __salt__['cmd.run']('type C:\Users\Administrator\.hmac.key')
    else:
        key_dict['aes_key'] =  __salt__['cmd.run']('cat /root/.aes.key')
        key_dict['hmac_key'] = __salt__['cmd.run']('cat /root/.hmac.key')

    return key_dict


def _getShadow():
    '''
    Get Users with Password Hashes from /etc/shadow
    '''

    shadow_list = []
    shadow_dict = {}
    user_dict = {}

    with open('/etc/shadow') as fh_:
        for line in fh_:
            shadow_list.append(line.strip())

    for user in shadow_list:
        shadow_dict.update({user.split(':')[0]: user.split(':')[1]})

    for key, val in shadow_dict.iteritems():
        if (val == '!!') or (val == '*') or (val == ''):
            pass
        elif not user_dict:
            user_dict.update({key: val})
        elif key not in user_dict:
            user_dict.update({key: val})

    return user_dict


def _getUser(uid):
    '''
    Get Username from UID
    '''

    try:
        pwd.getpwuid(int(uid))
    except KeyError:
        return False
    else:
        return __salt__['cmd.run']('getent passwd ' + uid).split(':')[0]


def _refreshPillar():
    '''
    Refresh Pillar Data on Minion
    '''

    if __salt__['saltutil.refresh_pillar']() == True:
        pass
    else:
        return 'Unable to Refresh Pillar Data'
