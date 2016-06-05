#!/usr/bin/python
# -*- coding: utf-8 -*-
import ldap
from ansible.module_utils.basic import *

import hashlib
from base64 import encodestring as encode
from base64 import decodestring as decode
import ldap.modlist as modlist


def checkPassword(challenge_password, password):
    challenge_bytes = decode(challenge_password[6:])
    digest = challenge_bytes[:20]
    salt = challenge_bytes[20:]
    hr = hashlib.sha1(password)
    hr.update(salt)
    return digest == hr.digest()


def makeSecret(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + encode(h.digest() + salt)


class ldap_binding_for_module(object):

    def __init__(self, calling_module):
        self.host = calling_module.params['ldap_host']
        self.dn = calling_module.params['bind_dn']
        self.passwd = calling_module.params['bind_pwd']
        self.calling_module = calling_module
        self.l = None

    def __enter__(self):
        try:
            self.l = ldap.open(self.host)
            self.l.simple_bind_s(self.dn, self.passwd)
            return self.l
        except Exception as e:
            self.calling_module.fail_json(
                msg="Unable to connect to ldap server '{}'. Exception was '{}'."
                    .format(self.host, str(e)))

    def __exit__(self, type, value, traceback):
        if self.l:
            self.l.unbind_s()


def main():
    module = AnsibleModule(
      argument_spec=dict(
        bind_dn=dict(required=True),
        bind_pwd=dict(required=True, no_log=True),
        ldap_host=dict(required=True),
        name=dict(required=True),
        user_cn=dict(required=False, default=None),
        user_password=dict(required=True, no_log=True),
        user_description=dict(required=False, default=None)
        ),
      supports_check_mode=True
      )

    user_dn = module.params['name']
    user_cn = module.params['user_cn']
    user_password = module.params['user_password']
    user_description = module.params['user_description']

    password_unchanged = False

    with ldap_binding_for_module(module) as l:

        try:
            ldap_result = l.search_s(user_dn, ldap.SCOPE_SUBTREE)
            if ldap_result:
                object_found = True
                (dn, current_object) = ldap_result[0]

                password_unchanged = checkPassword(
                    current_object['userPassword'][0],
                    user_password)

                any_change = (
                    (not password_unchanged)
                    or (user_cn and 'cn' in current_object and current_object.get('cn')[0] != user_cn)
                    or ('description' in current_object and current_object.get('description')[0] != user_description)
                )

                if not any_change:
                    module.exit_json(changed=False,
                                     user_dn=dn,
                                     user_record=current_object)
                elif module.check_mode:
                    module.exit_json(changed=True,
                                     user_dn=dn,
                                     user_record=current_object)
        except ldap.NO_SUCH_OBJECT:
            if module.check_mode:
                module.exit_json(
                  changed=True,
                  user_dn=user_dn)
            object_found = False
        except ldap.LDAPError as e:
            module.fail_json(
                msg="Unable to query ldap server  for '{}'.Exception was '{}'."
                    .format(user_dn, str(e)))

        try:
            attrs = {}
            attrs['objectclass'] = ['top',
                                    'organizationalRole',
                                    'simpleSecurityObject']
            if user_cn:
                attrs['cn'] = user_cn

            if password_unchanged:
                attrs['userPassword'] = current_object.get('userPassword')
            else:
                attrs['userPassword'] = makeSecret(user_password)

            if user_description:
                attrs['description'] = user_description
            # Convert the attributes dictionary to appropriate syntax
            #    for the add-function

            if object_found:
                if current_object.get('cn') and not user_cn:
                    attrs['cn'] = current_object['cn'][0]
                ldif_record = modlist.modifyModlist(current_object, attrs)
                l.modify_s(user_dn, ldif_record)
                module.exit_json(changed=True, previous_record=current_object)

            else:
                ldif_record = modlist.addModlist(attrs)
                l.add_s(user_dn, ldif_record)
                module.exit_json(changed=True)

        except ldap.LDAPError as e:
            module.fail_json(
                msg="Unable to register record for '{}'.Exception was '{}'."
                    .format(user_dn, str(e)))


if __name__ == '__main__':
    main()
