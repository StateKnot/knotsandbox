"""One-time native master-realm private frontend initialization; never resets users or unrelated policy."""
import json
import ssl
from urllib import request, parse, error
from identity import require
from verify import Admin, NoRedirect


def configure_master(admin, private_origin):
    current=admin.call('/admin/realms/master')
    attributes=dict(current.get('attributes') or {})
    previous=attributes.get('frontendUrl')
    if previous==private_origin:return False
    require(previous in (None,''), 'master frontendUrl drift; audited explicit migration required')
    attributes['frontendUrl']=private_origin
    # RealmRepresentation partial update: preserve all other attributes, do not send users/roles/credentials.
    admin.call('/admin/realms/master','PUT',{'attributes':attributes})
    return True


def bootstrap(s, material):
    origin=s['admin_url']
    creds=material['keycloak-bootstrap']
    body=parse.urlencode({'client_id':'admin-cli','grant_type':'password',
        'username':creds['username'].decode(),'password':creds['password'].decode()}).encode()
    opener=request.build_opener(request.ProxyHandler({}),
        request.HTTPSHandler(context=ssl.create_default_context(cafile=s['proxy_ca_file'])),NoRedirect())
    try:
        with opener.open(request.Request(origin+'/realms/master/protocol/openid-connect/token',data=body),timeout=10) as response:
            data=response.read(65537)
            require(len(data)<=65536,'bootstrap response too large')
            token=json.loads(data)['access_token']
    except error.HTTPError as e:
        raise ValueError(f'private bootstrap refused (HTTP {e.code}); credentials/body omitted') from None
    configure_master(Admin(origin,token,s['proxy_ca_file']),origin)
