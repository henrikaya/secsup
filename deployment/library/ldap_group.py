#!/usr/bin/python
# -*- coding: utf-8 -*-
import ldap
from ansible.module_utils.basic import *

import hashlib
from base64 import encodestring as encode
from base64 import decodestring as decode
import ldap.modlist as modlist



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
        object_class=dict(required=True),
        ),
      supports_check_mode=True
      )

    group_dn = module.params['name']
    admin_dn= module.params['bind_dn']
    object_class = module.params['object_class']


    with ldap_binding_for_module(module) as l:

        try:
            ldap_result = l.search_s(group_dn, ldap.SCOPE_SUBTREE)
            if ldap_result:
                (dn, current_object) = ldap_result[0]

                module.exit_json(changed=False,
                                 group_dn=dn,
                                 group_record=current_object)
        except ldap.NO_SUCH_OBJECT:
            if module.check_mode:
                module.exit_json(
                  changed=True,
                  group_dn=group_dn)
        except ldap.LDAPError as e:
            module.fail_json(
                msg="Unable to query ldap server  for '{}'.Exception was '{}'."
                    .format(group_dn, str(e)))

        try:
            attrs = {}
            attrs['objectclass'] = ['top',
                                    object_class]

            if object_class == 'groupOfNames':
                # At creation, a member is mandatory : let's put the admin account as member until a human decides otherwise
                attrs['member'] = admin_dn

            ldif_record = modlist.addModlist(attrs)
            l.add_s(group_dn, ldif_record)
            module.exit_json(changed=True, group_dn=group_dn)

        except ldap.LDAPError as e:
            module.fail_json(
                msg="Unable to register record for '{}'.Exception was '{}'."
                    .format(group_dn, str(e)))


if __name__ == '__main__':
    main()
