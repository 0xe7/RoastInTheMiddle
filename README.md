Roast in the Middle is a rough proof of concept (not attack-ready) that implements a man-in-the-middle ARP spoof to intercept AS-REQ's to modify and replay to perform a Kerberoast attack.

For more information about this attack, read the blog post [All Ur AS Are Belong To Us](https://www.semperis.com/blog/new-attack-paths-as-requested-sts).

To run this proof of concept [npcap](https://npcap.com/) needs to be installed on the machine and administrative privileges are required. This is because to perform the MitM it uses [sharppcap](https://github.com/dotpcap/sharppcap).

Some of the code to decode Kerberos traffic is taken from [Rubeus](https://github.com/GhostPack/Rubeus).

## Arguments

All arguments are mandatory.

* /listenip:IP - IP address to listen on
* /spns:SPNs - SPNs or usernames to kerberoast (can be a file or comma separated values)
* /targets:IP1,IP2... - IP addresses of targets to man-in-the-middle
* /dcs:IP1,IP2... - IP addresses of domain controllers

This proof of concept will only be useful if the attack machine, targets and domain controllers are all on the same network segment due to the reliance on ARP spoofing, it could be modified to support a gateway for either the targets or DCs.
