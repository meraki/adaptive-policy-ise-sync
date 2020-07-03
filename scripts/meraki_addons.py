def meraki_create_sgt(db, organizationId, **kwargs):
    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'groups'],
        'operation': 'createOrganizationAdaptivePolicyGroup',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/groups'

    body_params = ['value', 'name', 'description', 'networkObjectId']
    payload = {k: v for (k, v) in kwargs.items() if k in body_params}

    return db._session.post(metadata, resource, payload)


def meraki_read_sgt(db, organizationId):
    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'groups'],
        'operation': 'getOrganizationAdaptivePolicyGroups',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/groups'

    return db._session.get(metadata, resource)


def meraki_update_sgt(db, organizationId, groupId: str, **kwargs):
    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'groups'],
        'operation': 'updateOrganizationAdaptivePolicyGroup',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/groups/{groupId}'

    if "value" in kwargs:
        post_resource = f'/organizations/{organizationId}/adaptivePolicy/groups'

        body_params = ['name', 'description', 'networkObjectId', 'value']
        payload = {k: v for (k, v) in kwargs.items() if k in body_params}

        new = db._session.post(metadata, post_resource, payload)
        db._session.delete(metadata, resource)
        return new
    else:
        body_params = ['name', 'description', 'networkObjectId']
        payload = {k: v for (k, v) in kwargs.items() if k in body_params}

        return db._session.put(metadata, resource, payload)


def meraki_delete_sgt(db, organizationId, groupId: str):
    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'groups'],
        'operation': 'deleteOrganizationAdaptivePolicyGroup',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/groups/{groupId}'

    return db._session.delete(metadata, resource)


def meraki_create_sgacl(db, organizationId, **kwargs):
    if 'ipVersion' in kwargs:
        options = ['agnostic', 'ipv4', 'ipv6']
        assert kwargs[
                   'ipVersion'] in options, f'''"ipVersion" cannot be "{kwargs['ipVersion']}", & must be set to \
                   one of: {options}'''

    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'acls'],
        'operation': 'createOrganizationAdaptivePolicyAcl',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/acls'

    body_params = ['name', 'description', 'rules', 'ipVersion']
    payload = {k: v for (k, v) in kwargs.items() if k in body_params}

    return db._session.post(metadata, resource, payload)


def meraki_read_sgacl(db, organizationId):
    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'acls'],
        'operation': 'getOrganizationAdaptivePolicyAcls',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/acls'

    return db._session.get(metadata, resource)


def meraki_update_sgacl(db, organizationId, aclId: str, **kwargs):
    if 'ipVersion' in kwargs:
        options = ['agnostic', 'ipv4', 'ipv6']
        assert kwargs[
                   'ipVersion'] in options, f'''"ipVersion" cannot be "{kwargs['ipVersion']}", & must be set to \
                   one of: {options}'''

    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'acls'],
        'operation': 'updateOrganizationAdaptivePolicyAcl',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/acls/{aclId}'

    body_params = ['name', 'description', 'rules', 'ipVersion']
    payload = {k: v for (k, v) in kwargs.items() if k in body_params}

    return db._session.put(metadata, resource, payload)


def meraki_delete_sgacl(db, organizationId, aclId: str):
    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'acls'],
        'operation': 'deleteOrganizationAdaptivePolicyAcl',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/acls/{aclId}'

    return db._session.delete(metadata, resource)


def meraki_read_sgpolicy(db, organizationId):
    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'bindings'],
        'operation': 'getOrganizationAdaptivePolicyBindings',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/bindings'

    return db._session.get(metadata, resource)


def meraki_update_sgpolicy(db, organizationId, **kwargs):
    if 'catchAllRule' in kwargs:
        options = ['global', 'deny all', 'allow all']
        assert kwargs[
                   'catchAllRule'] in options, f'''"catchAllRule" cannot be "{kwargs['catchAllRule']}", & must be set \
                   to one of: {options}'''

    metadata = {
        'tags': ['organizations', 'configure', 'adaptivePolicy', 'bindings'],
        'operation': 'updateOrganizationAdaptivePolicyBindings',
    }
    resource = f'/organizations/{organizationId}/adaptivePolicy/bindings'

    body_params = ['srcGroupId', 'dstGroupId', 'name', 'description', 'aclIds', 'catchAllRule', 'bindingEnabled',
                   'monitorModeEnabled']
    payload = {k: v for (k, v) in kwargs.items() if k in body_params}

    return db._session.put(metadata, resource, payload)
