# DHCP Implement

## 169.254.x.x

* APIPA (Automatic Private IP Addressing) is a networking feature that allows a device to automatically self-assign an IPv4 address when it cannot reach a Dynamic Host Configuration Protocol (DHCP) server.

* How APIPA Works
  -	IP Address Range: Automatically assigns an address in the 169.254.0.0 to 169.254.255.254 block (specifically 169.254.1.0 through 169.254.254.255) with a subnet mask of 255.255.0.0.
  -	Conflict Avoidance: The device randomly picks an address from this range and uses Address Resolution Protocol (ARP) to make sure no other device on the local network is already using it.
  -	Background Check: After self-assigning an APIPA address, the device continues to broadcast and check for a DHCP server (typically every 3 to 5 minutes). If a DHCP server comes online, it replaces the APIPA address with a valid dynamic IP. [1, 2, 3]

* Key Limitations
  -	Local-Only Communication: Devices with an APIPA address can only talk to other devices on the same local subnet that also have APIPA addresses.
  -	No Internet or Routing: It does not provide a default gateway, meaning APIPA-enabled devices cannot access the internet or communicate across different networks.
  -	Troubleshooting Indicator: Seeing an IP starting with 169.254.x.x (via commands like ipconfig) usually acts as a warning sign that your device failed to talk to your DHCP server or router.

* A device will self-assign an APIPA address the moment it is configured to obtain an IP address automatically but fails to get a response from a DHCP server.

* Specifically, the process triggers during these exact scenarios:
  -	During Boot-Up or Network Connection: When you turn on your device, plug in an Ethernet cable, or connect to a Wi-Fi network, it sends out a broadcast request looking for a DHCP server (usually your router). If the router doesn't answer after a few seconds, the device gives up and assigns itself an APIPA address.
  -	When a DHCP Lease Expires: IP addresses given by routers aren't permanent; they are "leased" for a specific amount of time (e.g., 24 hours). When that time is up, your device tries to renew the lease. If the router is offline or unresponsive at that exact moment, the device drops its old IP and switches to APIPA.
  -	After a Network Disconnection: If your network connection drops temporarily and reconnects, the device will re-initiate the DHCP process. If the handshake fails during reconnection, APIPA takes over.

* Common Root Causes:
  -	The router or DHCP server is powered off or frozen.
  -	The Ethernet cable is damaged, or the Wi-Fi signal is too weak to complete the handshake.
  -	The router has run out of available IP addresses to hand out.

* Type the following command to drop the APIPA address and press Enter:
```cmd
ipconfig /release
```

* Type the following command to ask your router for a new IP and press Enter:
```cmd
ipconfig /renew
```

Note: If the screen freezes or returns an error like "unable to contact your DHCP server," your computer still cannot physically talk to the router.

## DHCP Process

1. DHCP Discover (Broadcast)
2. DHCP Offer (Unicast/Broadcast)
3. DHCP Request (Broadcast)
4. DHCP ACK (Unicast/Broadcast)

* Details

1. Discover – The PC Asks for Help
Because the PC does not yet have an IP address, it cannot communicate directly with any specific device. It sends out a DHCP Discover packet to see if any DHCP servers are listening.
*	Source IP: 0.0.0.0 (Since it doesn't have one yet)
*	Destination IP: 255.255.255.255 (IPv4 Broadcast — sent to everyone on the local network)
*	Source MAC: The PC's actual physical hardware address
*	Destination MAC: FF:FF:FF:FF:FF:FF (Layer 2 Broadcast)

2. Offer – The Server Responds
Every DHCP server on the local segment receives the broadcast. A server that has an available pool of IP addresses will reserve one and respond to the PC with a DHCP Offer. This message contains the proposed configuration.
*	What's inside: A proposed IP address for the PC, the Subnet Mask, the Default Gateway (router) IP, DNS server IPs, and a Lease Time (how long the PC can keep the IP).
*	Delivery: Depending on the server configuration and OS implementation, this is either sent as a Unicast directly back to the PC’s MAC address or as a Broadcast.

3. Request – The PC Chooses an Offer
If there are multiple DHCP servers, the PC typically accepts the first offer it receives. It sends a DHCP Request packet back to the network.
*	Why Broadcast? This packet is explicitly sent as a broadcast even though it is responding to a specific server. It does this to formally accept the chosen server's offer while simultaneously signaling to any other DHCP servers that their offers were declined, allowing them to release their reserved IPs back into their pools.
*	Source IP: Still 0.0.0.0 (It hasn't officially bound the IP address yet)
*	Destination IP: 255.255.255.255

4. Ack – The Server Finalizes the Deal
The server that made the chosen offer receives the request. It finalizes the lease in its database and responds with a DHCP Acknowledgment (ACK) packet.
*	The Result: Upon receiving the ACK, the PC officially binds the IP address, configures its network interface with the subnet mask and default gateway, and completes its connection to the network.

## DHCP Helper

