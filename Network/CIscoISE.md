# Cisco ISE

## Basic Knowledge

* The Cisco Integrated Management Controller (IMC) is a built-in baseboard management controller (BMC) that provides embedded, out-of-band server management for Cisco UCS C-Series Rack Servers and S-Series Storage Servers. It allows administrators to deploy, configure, and monitor hardware remotely, regardless of the server's power state.
  - Core Capabilities: Cisco IMC operates as an independent, "lights-out" management entity. Key tasks include:
    - Remote Presence: Provides remote keyboard, video, and mouse (KVM) access and virtual media mounting.
    - Hardware Lifecycle: Manages BIOS configuration, server boot order, and firmware updates.
    - Power Management: Allows administrators to power on, power off, power cycle, or reset the server remotely.
    - Monitoring & Alerts: Tracks hardware health, fan sensors, and temperatures, while managing event filters and fault alarms.
    - Security & Access: Handles local user accounts, Active Directory integration, and platform security.

* Cisco Identity Services Engine (ISE) is a comprehensive network access control (NAC) and policy management platform. It acts as the "brain" of your network security, continuously identifying users and devices, evaluating their compliance, and enforcing strict zero-trust access policies across wired, wireless, and VPN environments.
  - Core Capabilities
    - Authentication and Authorization: Functions as a centralized AAA (Authentication, Authorization, and Accounting) server. It verifies exactly who is connecting and grants them only the access they need.
    - Device Profiling: Automatically identifies and classifies the types of devices on your network (e.g., employee laptops, IoT sensors, guest smartphones, or printers) to apply tailored access levels.
    - Posture Assessment: Checks the health, security posture, and compliance of a device (like ensuring the antivirus is up to date) before allowing it onto the corporate network.
    - Threat Containment: Acts dynamically by isolating or disconnecting compromised endpoints, preventing threats from moving laterally across the network.

* CIMC vs Cisco ISE
  - In network architecture, CIMC (Cisco Integrated Management Controller) and ISE (Identity Services Engine) serve distinct but related purposes. CIMC is the out-of-band hardware management for Cisco physical appliances, while ISE operates as the central policy and AAA (Authentication, Authorization, and Accounting) server.

  - 1. CIMC (Cisco Integrated Management Controller)
       - Purpose: Out-of-band server hardware management (IPMI-equivalent). Used for remote power control, ISO mounting (for ISE installation), and hardware health monitoring.
       - Network Placement: Connected to the management network or out-of-band (OOB) switch via a dedicated Mgmt port (typically port #9 on Cisco SNS appliances).
       - Logical Flow: Admin Workstation → OOB Management Switch → CIMC Interface → Server Hardware (KVM).
  - 2. Cisco ISE (Identity Services Engine)
       - Purpose: Centralized RADIUS/TACACS+ AAA server for enterprise network access control (wired, wireless, VPN).
       - Network Placement: Deployed as virtual machines, on hardware (Secure Network Server), or in the cloud. Distributed deployments separate ISE roles (Personas) across the network:
       - PAN (Primary Administration Node): Behind the Data Center firewall for centralized policy configuration.
       - MnT (Monitoring Node): Behind the Data Center firewall for log collection.
       - PSN (Policy Service Node): Placed in local sites (behind perimeter firewalls) to handle local AAA requests without overloading the WAN.
       - Logical Flow: Authenticating Devices (APs, Switches) → Secure Network Fabric (RADIUS/TACACS+) → ISE PSN.

## Resource

* [What is Cisco ISE?](https://www.techtarget.com/searchmobilecomputing/definition/Cisco-Identity-Services-Engine-ISE)

* [Cisco Integrated Management Controller (IMC)](https://www.cisco.com/site/us/en/products/computing/servers-unified-computing-systems/ucs-integrated-management-controller-cimc/index.html)

* [Configuring the CIMC and Installing Cisco ISE on an SNS Appliance](https://www.youtube.com/watch?v=8jMhvW1LWns&t=1s)

* [Placement of Cisco ISE and WLC in Network Architecture](https://www.experts-exchange.com/questions/29263929/Placement-of-Cisco-ISE-and-WLC-in-Network-Architecture.html)

* [Cisco ISE 3D Network Diagram Topology](https://jmxi.io/cisco-ise-network-diagram)
