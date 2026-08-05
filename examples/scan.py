
# This script scans for nearby LDN networks and prints information about them.

import ldn
import trio
import os

AcceptPolicies = {
    ldn.ACCEPT_ALL: "ALL",
    ldn.ACCEPT_NONE: "NONE",
    ldn.ACCEPT_BLACKLIST: "BLACKLIST",
    ldn.ACCEPT_WHITELIST: "WHITELIST"
}

BandNames ={
    2: "2.4 GHz",
    5: "5 GHz"
}

Platforms = {
    ldn.PLATFORM_NX: "Switch",
    ldn.PLATFORM_OUNCE: "Switch 2"
}

async def main():
    keys = ldn.load_keys("prod.keys")
    networks = await ldn.scan(keys=keys, ldnd_socket=os.environ["LDN_DAEMON"])

    print("Found %i network(s)" %len(networks))
    for i, network in enumerate(networks):
        print()
        print("Network %i:" %i)
        print("\tLocal communication id: %016x" %network.local_communication_id)
        print("\tScene id: %i" %network.scene_id)
        print()
        print("\tStation accept policy: %s" %AcceptPolicies[network.accept_policy])
        print("\tMaximum number of participants: %i" %network.max_participants)
        print("\tApplication data: %s (%i bytes)" %(network.application_data.hex(), len(network.application_data)))
        print()
        print("\tHost address: %s" %network.address)
        print("\tWLAN band: %s" %BandNames[network.band])
        print("\tWLAN channel: %i" %network.channel)
        print("\tSSID: %s" %network.ssid.hex())
        print()
        print("\tLDN version: %i" %network.version)
        print("\tSecurity mode: %i" %network.security_mode)
        print()
        print("\tParticipants:")
        for i, participant in enumerate(network.participants):
            if participant.connected:
                print("\t\tName: %s" %participant.name.decode())
                print("\t\tIP address: %s" %participant.ip_address)
                print("\t\tMAC address: %s" %participant.mac_address)
                print("\t\tApplication version: %i" %participant.app_version)
                print("\t\tPlatform: %s" %Platforms[participant.platform])
                print("\t\tConnected: %s" %participant.connected)
                print("\t\t---")
        
trio.run(main)
