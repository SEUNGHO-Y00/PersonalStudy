# Step

1. Two Switches Connect
2. Setting up Vlan and Trunking in Switches
3. Connect Taclanes
4. Setting Native Vlan
5. Connect Firewall
6. Setting Vlan and Zone in Firewall

# Study Resource

## VLAN

The core difference between a Layer 2 (L2) and Layer 3 (L3) VLAN is how traffic travels between them: L2 VLANs segregate traffic within a single broadcast domain using MAC addresses, while L3 VLANs use IP addresses to route traffic directly between different networks.

* Layer 2 VLANs

  - How they work: Segment a physical switch into multiple virtual broadcast domains using Layer 2 logic (MAC addresses).
  - Scope: Every port assigned to an L2 VLAN is in the same IP subnet.
  - Communication: Devices inside the same L2 VLAN can communicate directly using their MAC addresses.
  - Limitation: To talk to a device in another VLAN, the traffic must leave the L2 environment and go through an external router.

* Layer 3 VLANs

  - How they work: Combine the fast, hardware-based packet forwarding of switches with the intelligence of IP routing.
  - Scope: L3 VLANs operate across multiple distinct IP subnets.
  - Communication: Devices in different L3 VLANs can communicate directly through the switch (using a Switched Virtual Interface or SVI) without needing an external router.
  - Benefits: Speeds up inter-VLAN routing, reduces latency, and allows for advanced security like Access Control Lists (ACLs) to manage traffic flow based on IP addresses and ports.

## Firewall

A Layer 2 (transparent) firewall handles VLANs by acting as an invisible security filter right in the middle of a VLAN segment or an 802.1Q trunk link. Because it does not have an IP address on these segments, it uses specialized techniques to inspect and pass VLAN-tagged traffic without breaking your broadcast domains.

* [transparent-firewall](https://www.fortinet.com/resources/cyberglossary/transparent-firewall)

* [Palo Alto Firewall](https://www.wiresandwi.fi/blog/palo-alto-basic-setup)

* 
