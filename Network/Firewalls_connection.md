# Firewalls connection

In Palo Alto Networks PAN-OS, a Virtual Router (VR) is a software-defined routing engine running inside a single physical firewall. It functions identically to a VRF (Virtual Routing and Forwarding) instance on a Cisco router, allowing you to completely isolate routing tables, paths, and protocols between different interfaces.
Every Layer 3 interface on a Palo Alto firewall must be bound to a Virtual Router to forward traffic. By default, PAN-OS provides a single VR named default, but you can create multiple custom virtual routers to achieve advanced network architectures.

Core Functions of a Virtual Router

• Maintains Independent Routing Tables: Each VR has its own distinct routing information base (RIB) and forwarding information base (FIB).
• Handles Static and Dynamic Routing: A VR can independently run OSPF, BGP, RIP, and BFD, or hold thousands of static routing entries.
• Separates Network Spaces: You can place your corporate WAN interfaces into one VR and your internal horizontal LAN segments into another, keeping their routing paths completely isolated.

Why Use Multiple Virtual Routers? (Real-World Use Cases)


1. Preventing Asymmetric Routing in Multi-WAN Setups

If your company has two ISPs (e.g., AT&T and Comcast) and you want to ensure that traffic entering AT&T always replies out of AT&T, you can place each ISP into its own separate Virtual Router. This isolates the default paths and prevents the firewall from routing responses out of the wrong internet circuit.

2. Managing Overlapping IP Subnets (Company Mergers)

If your company acquires another organization and both networks heavily use the 192.168.10.0/24 subnet, plugging them into the same routing table will cause a collision. By placing the acquired network into a custom VR (e.g., VR-Acquisition), you keep the routing tables separate and use Inter-VR NAT to translate traffic between them safely.

3. Strict ISP Egress Control

In the horizontal peer link setup we discussed earlier, both firewalls likely have their own local internet gateways. If you want to ensure that Firewall 1's local network traffic never uses Firewall 2's internet path—even if a primary link fails—keeping their routes inside separate Virtual Routers guarantees logical isolation.

Inter-VR Routing: How Virtual Routers Talk to Each Other

While Virtual Routers isolate traffic by default, you frequently need to leak routes between them (e.g., allowing an internal user VR to access a shared management VR). Palo Alto handles this elegantly using Next-Hop VR Static Routes or a Logical Loopback Cable.

The Next-Hop VR Method (Most Common)

Instead of pointing a static route to a physical IP address, you point the static route to the name of the destination Virtual Router.
• Example in the GUI:
	• Destination: 10.20.0.0/16
	• Interface: (Leave blank)
	• Next Hop: Select Next VR from the dropdown menu.
	• Target VR: Select your peer virtual router name (e.g., VR-Internal).

Senior Engineer's Architecture Rule: Virtual Routers vs. Security Zones

A common point of confusion for engineers transitioning to Palo Alto is mixing up Virtual Routers and Security Zones.
• Virtual Routers handle Layer 3 topology logic. They determine if a path physically exists to a destination and where to forward the packet next.
• Security Zones handle Layer 4–7 policy enforcement. They determine if the traffic is actually allowed to pass through based on your security rules.
Takeaway: A packet crossing the firewall must pass both checks. It must successfully find a route via its assigned Virtual Router, and it must match a security rule that explicitly allows communication between the source and destination Security Zones.
Are you planning to run dynamic routing protocols (like OSPF or BGP) inside your Virtual Router to talk to your core switches, or are you keeping the layout simple with static routes? Use markdown bolding on your routing type preference so I can give you a tailored GUI example.
