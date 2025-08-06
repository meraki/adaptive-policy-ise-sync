from sync.models import Organization, Dashboard, ISEServer, SyncSession
# from django.forms.models import model_to_dict


def run():
    ise_ip = input("Enter the ISE IP Address:")
    ise_un = input("Enter the ISE Username:")
    ise_pw = input("Enter the ISE Password:")
    meraki_api_url = input("Enter the Meraki Dashboard API Path (Enter=https://api.meraki.com/api/v1/):") or "https://api.meraki.com/api/v1/"
    meraki_api_key = input("Enter your Meraki API Key:")
    meraki_api_org = input("Enter your Meraki Organization ID:")
    sync_timer = input("Enter the manual sync timer (Enter=240 seconds):") or "240"

    i_s = ISEServer.objects.create(description="ISE Server", ipaddress=ise_ip, username=ise_un, password=ise_pw,
                                   pxgrid_enable=False)
    print("Created", i_s)

    o = Organization.objects.create(orgid=meraki_api_org)
    d = Dashboard.objects.create(description="Meraki Dashboard", apikey=meraki_api_key, baseurl=meraki_api_url)
    d.organization.add(o)
    d.save()
    print("Created", o)
    print("Created", d)

    s_s = SyncSession.objects.create(description="TrustSec Sync", dashboard=d, iseserver=i_s,
                                     ise_source=True, sync_interval=int(sync_timer), sync_enabled=True,
                                     apply_changes=True)
    print("Created", s_s)
