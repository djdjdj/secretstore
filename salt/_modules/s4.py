# -*- coding: utf-8 -*-
'''
:maintainer: Dan McTeer (mcteer@adobe.com)
:maturity: new
:requires: s4 External Pillar
:platform: all
'''

from __future__ import absolute_import

try:
    import json, logging, os, pwd, random, salt, string, sys, time, yaml, zlib
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256
except ImportError, imperr:
    err_list = str(imperr).split(' ')
    print 'Unable to import module: ' + err_list[3]

LOG = logging.getLogger(__name__)


## Public Functions ##


def gen_bundles(*args):
    '''
    Generate AES/HMAC Encrypted Bundle
    '''

    secrets = {}

    ## Check for Supported OS ##
    if __salt__['grains.get']('os') == 'Windows':
        return 'Unsupported Operating System'

    if _checkCAEnv() == True:
        if not args:
            if not __salt__['pillar.get']('cmdb:secrets'):
                if not __salt__['pillar.get']('bundle_users'):
                    return 'No Bundles to Create'
                else:
                    _refreshPillar()
                    user_vault = _cleanVault(_getLocalSecrets([]))
                    if not user_vault:
                        return 'No Bundles to Create'
                    else:
                        _writeBundle(user_vault)

                    return 'Encrypted Bundle(s) Successfully Created'
            else:
                _refreshPillar()
                user_vault = _cleanVault(_getCMDBSecrets([]))
                if not user_vault:
                    return 'No Bundles to Create'
                else:
                    _writeBundle(user_vault)

                return 'Encrypted Bundle(s) Successfully Created'
        else:
            if not __salt__['pillar.get']('cmdb:secrets'):
                if not __salt__['pillar.get']('bundle_users'):
                    return 'No Bundles to Create'
                else:
                    _refreshPillar()
                    user_vault = _cleanVault(_getLocalSecrets(args))
                    if not user_vault:
                        return 'No Bundles to Create'
                    else:
                        _writeBundle(user_vault)

                    return 'Encrypted Bundle(s) Successfully Created'
            else:
                _refreshPillar()
                user_vault = _cleanVault(_getCMDBSecrets(args))
                if not user_vault:
                    return 'No Bundles to Create'
                else:
                    _writeBundle(user_vault)

                return 'Encrypted Bundle(s) Successfully Created'
    else:
        return _checkCAEnv()


def gen_keys():
    '''
    Generate AES/HMAC Keys
    '''

    key_dict = {'aes': 16, 'hmac': 9}

    ## Check for Supported OS ##
    if __salt__['grains.get']('os') == 'Windows':
        return 'Unsupported Operating System'

    for key, val in key_dict.iteritems():
        key_dict[key] = str(_genRandom(val))
        with open('/root/.' + key + '.key', 'w') as fh_:
            fh_.write(key_dict[key] + '\n')
        os.chmod('/root/.' + key + '.key', 0400)

    return 'AES/HMAC Keys Generated'


def get_secrets(*args):
    '''
    Retrieve specified secret from s4
    '''

    secret_dict = {}

    if not args:
        return 'Please Specify Secret(s) to View'
    else:
        _refreshPillar()
        for secret in args:
            if not __salt__['pillar.get']('cmdb:secrets:' + secret):
                secret_dict.update({secret: __salt__['pillar.get'](secret)})
            else:
                secret_dict.update({secret: __salt__['pillar.get']('cmdb:secrets:' + secret)})

    return secret_dict


def list_bundles():
    '''
    View All Encrypted Bundles on Target Minion
    '''

    bundles = []

    ## Check for Supported OS ##
    if __salt__['grains.get']('os') == 'Windows':
        return 'Unsupported Operating System'

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
                user = _getUser(item.replace('.asc', ''))
                bundles.append(item + ' (' + user + ')')
    elif not bundles:
        return 'No Encrypted Bundles'
    else:
        return 'No Encrypted Bundles'

    return bundles


def list_secrets():
    '''
    List Available Secrets
    '''

    secrets_list = []

    _refreshPillar()
    for key, val in __salt__['pillar.items']().iteritems():
        if 'password' in val:
            secrets_list.append(key)
        else:
            continue

    if 'secrets' not in __salt__['pillar.get']('cmdb'):
        return secrets_list
    else:
        for key, val in __salt__['pillar.get']('cmdb:secrets').iteritems():
            if key not in secrets_list:
                if 'password' in val:
                    secrets_list.append(key)
                else:
                    continue
            else:
                continue

        return secrets_list


def view_bundles(*args):
    '''
    View the Contents of Target Encrypted Bundle
    '''

    result_set = {}

    ## Check for Supported OS ##
    if __salt__['grains.get']('os') == 'Windows':
        return 'Unsupported Operating System'

    if not args:
        return 'Please Specify Service Account'
    else:
        for account in args:
            if not __salt__['user.info'](account):
                result_set.update({account: 'User Does Not Exist'})
            else:
                bundle = str(__salt__['user.info'](account)['uid'])
                if os.path.isfile('/home/charlie/' + bundle + '.asc') == False:
                    return 'No Bundle Available for Specified User'
                else:
                    result_set.update({account: _aesDecrypt('/home/charlie/' + bundle + '.asc')})

    return result_set



## Private Functions ##

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


def _aesEncrypt(json_vault):
    '''
    Encrypt Secrets Bundle
    '''

    key_dict = _getKeyPair()

    # Get Decrypted Keys #
    aes_key = str(key_dict['aes_key']).rstrip('\n')
    hmac_key = str(key_dict['hmac_key']).rstrip('\n')

    # Compress Vault #
    init_val = os.urandom(AES.block_size)
    compress_vault = zlib.compress(json_vault.encode('utf-8'))

    # Encrypt Vault #
    aes = AES.new(aes_key, AES.MODE_CFB, init_val)
    cipher_text = init_val + aes.encrypt(compress_vault)
    hmac = HMAC.new(hmac_key, cipher_text, SHA256)
    cipher = hmac.digest() + cipher_text

    return cipher


def _checkCAEnv():
    '''
    Check Child Architecture Requirements
    '''

    if not __salt__['user.info']('charlie'):
        return 'Secrets User (charlie) Does Not Exist'
    elif __salt__['file.directory_exists']('/home/charlie') == False:
        return '/home/charlie Does Not Exist'
    else:
        return True


def _checkUser(user):
    '''
    Check User on Local System
    '''

    try:
        pwd.getpwnam(user)
    except KeyError:
        return False
    else:
        return True


def _cleanVault(vault_dict):
    '''
    Clean Up/Prepare Secrets Dictionary for Bundling
    '''

    user_vault = {}
    ignore_list = ['users', 'device_service', 'environment_type', 'environment_name']

    for account, info in vault_dict.iteritems():
        if 'users' not in info:
            continue
        elif info['users'] == None:
            continue

        for user in info['users']:
            for key, val in info.iteritems():
                if not user_vault:
                    if key in ignore_list:
                        pass
                    else:
                        user_vault.update({user: {account: {key: val.strip()}}})
                elif user not in user_vault:
                    if key in ignore_list:
                        pass
                    else:
                        user_vault.update({user: {account: {key: val.strip()}}})
                elif account not in user_vault[user]:
                    if key in ignore_list:
                        pass
                    else:
                        user_vault[user].update({account: {key: val.strip()}})
                else:
                    if key in user_vault[user][account]:
                        pass
                    elif key in ignore_list:
                        pass
                    else:
                        user_vault[user][account].update({key: val.strip()})

    return user_vault


def _convertVault(vault_dict):
    '''
    Convert Vault from YAML to JSON
    '''

    json_vault = json.dumps(vault_dict, sort_keys=True, indent=2, separators=(',', ':'))

    return json_vault


def _genRandom(num):
    '''
    Generate a Random String of Characters
    '''

    chars = string.letters + string.digits + '!@#%^&'
    random.seed = (os.urandom(1024))
    random_string = ''.join(random.SystemRandom().choice(chars) for _ in xrange(num))

    return random_string


def _getKeyPair():
    '''
    Get AES/HMAC Keys from Minion
    '''

    key_dict = {'aes_key': '', 'hmac_key': ''}

    key_dict['aes_key'] =  __salt__['cmd.run']('cat /root/.aes.key')
    key_dict['hmac_key'] = __salt__['cmd.run']('cat /root/.hmac.key')

    return key_dict


def _getCMDBSecrets(user_list):
    '''
    Get Secrets from CMDB
    '''

    secrets = {}

    _refreshPillar()

    if not user_list:
        secrets = __salt__['pillar.get']('cmdb:secrets')
    else:
        for user, keys in __salt__['pillar.get']('cmdb:secrets').iteritems():
            for account in user_list:
                if item in keys['users']:
                    secrets.update({user: __salt__['pillar.get']('cmdb:secrets:' + user)})
            for user, keys in secrets.iteritems():
                for item in keys['users']:
                    if item not in args:
                        keys['users'].remove(item)

    return secrets


def _getLocalSecrets(user_list):
    '''
    Get Pillar Data Local to the Salt Master
    '''

    secrets = {}

    _refreshPillar()

    if not user_list:
        for account, keys in __salt__['pillar.get']('bundle_users').iteritems():
            for item in keys:
                if 'password' in __salt__['pillar.get'](item):
                    secrets.update({item: __salt__['pillar.get'](item)})
                    if 'users' not in secrets[item]:
                        secrets[item].update({'users': [account]})
                    else:
                        secrets[item]['users'].append(account)
                else:
                    continue
            else:
                continue
    else:
        for account in user_list:
            if account not in __salt__['pillar.get']('bundle_users'):
                continue
            else:
                for item in __salt__['pillar.get']('bundle_users:' + account):
                    secrets.update({item: __salt__['pillar.get'](item)})
                    if 'users' not in secrets[item]:
                        secrets[item].update({'users': [account]})
                    else:
                        secrets[item]['users'].append(account)

    return secrets


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


def _writeBundle(user_vault):
    '''
    Create Encrypted Bundle on Target Minion
    '''

    for user, secrets in user_vault.iteritems():
        if _checkUser(user) == True:
            json_secrets = _convertVault(secrets)
            charlie_usr = int(__salt__['cmd.run']('id -u charlie'))
            bundle_usr = __salt__['cmd.run']('id -u ' + user)
            cipher = _aesEncrypt(json_secrets)
            with open('/home/charlie/' + bundle_usr + '.asc', 'w') as fh_:
                fh_.write(cipher)
            os.chown('/home/charlie/' + bundle_usr + '.asc', charlie_usr, charlie_usr)
            os.chmod('/home/charlie/' + bundle_usr + '.asc', 0600)
        else:
           continue
