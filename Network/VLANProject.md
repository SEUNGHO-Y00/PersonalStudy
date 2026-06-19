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

* VLAN tag

A VLAN tag is an identifier (a specific ID number) added to a data packet's header to indicate which virtual local network the packet belongs to. It allows network switches and routers to distinguish, separate, and route traffic from multiple isolated networks over a single physical cable or connection.

A clear way to understand VLAN tags and how they operate in a network includes:

How VLAN Tagging WorksThe Process: Defined by the IEEE 802.1Q standard, the network switch adds a small, 4-byte identifier (the VLAN ID) to an Ethernet frame as it enters the network.The Purpose: This tag tells every switch along the way which specific network the data belongs to (e.g., Guest Wi-Fi, Finance, or Security Cameras).Tag Removal: Once the data packet reaches its final destination, the tag is usually stripped away so the receiving device can process the standard Ethernet frame without needing to know about VLANs.Tagged vs. Untagged PortsTagged Ports (Trunks): Used to connect networking equipment like switches or routers. These ports handle traffic for multiple VLANs at once. The tag is necessary here so the receiving switch knows which VLAN the data belongs to.Untagged Ports (Access Ports): Usually connected to end-user devices like a PC, printer, or smart TV. Devices like computers do not understand VLAN tags. The port adds a tag to the data as it enters the network and removes the tag as it leaves the network.

* [How do you troubleshoot VLAN trunking issues?](https://www.linkedin.com/advice/3/how-do-you-troubleshoot-vlan-trunking-issues-lt2lf)

## Firewall

A Layer 2 (transparent) firewall handles VLANs by acting as an invisible security filter right in the middle of a VLAN segment or an 802.1Q trunk link. Because it does not have an IP address on these segments, it uses specialized techniques to inspect and pass VLAN-tagged traffic without breaking your broadcast domains.

* [transparent-firewall](https://www.fortinet.com/resources/cyberglossary/transparent-firewall)

* [Palo Alto Firewall](https://www.wiresandwi.fi/blog/palo-alto-basic-setup)

* 
