# Cisco ISR

* Cisco ISE is security software used to control and audit network access, while Cisco ISR is physical hardware used to route data traffic between different locations.

* Cisco ISE (Identity Services Engine) is a centralized Network Access Control (NAC) platform. It acts as a security gatekeeper. It determines exactly who and what is allowed onto your network.

* Cisco ISR (Integrated Services Router) is a physical, modular routing hardware device. It functions as a traffic director. It physically connects branch offices to corporate headquarters, data centers, and the internet.

## Knowledge

* A terminal server connects devices with a serial port to a local area network (LAN). Products marketed as terminal servers can be very simple devices that do not offer any security functionality, such as data encryption and user authentication. The primary application scenario is to enable serial devices to access network server applications, or vice versa, where security of the data on the LAN is not generally an issue. There are also many terminal servers on the market that have highly advanced security functionality to ensure that only qualified personnel can access various servers and that any data that is transmitted across the LAN, or over the Internet, is encrypted. Usually, companies that need a terminal server with these advanced functions want to remotely control, monitor, diagnose and troubleshoot equipment over a telecommunications network.

* A console server (also referred to as console access server, console management server, serial concentrator, or serial console server) is a device or service that provides access to the system console of a computing device via networking technologies.

* [Cisco Router as Terminal Server Or Access Server](https://www.youtube.com/watch?v=bY9dy95JbzE)

* [How to Configure Terminal Server in a Cisco device](https://www.youtube.com/watch?v=hHL-lwg3Qec)

* [Configure Terminal Server through Menu Options](https://www.cisco.com/c/en/us/support/docs/dial-access/asynchronous-connections/200462-Terminal-server-configuration-using-Menu.html)

## Pysical Location

* [Cisco 1100 Series Router](https://www.router-switch.com/c1111-8p.html)

* [Arista 720D Series Switch](https://www.arista.com/en/qsg-720d-series/720d-series-front-panel)

## SSH

* What is Cisco Crypto PKI?
  - Definition: A complete management subsystem for handling X.509 digital certificates, enrollment requests (CSRs), and Certificate Authority (CA) trust relationships.
  - Commands: Uses crypto pki trustpoint, crypto pki enroll, and crypto pki authenticate.
  - Purpose: Establishes scalable identity and mutual trust across multiple network devices by validating that a peer's certificate ties back to a shared, trusted CA.

* What is Cisco Crypto RSA?
  - Definition: An encryption and authentication algorithm used to create a pair of keys (one public, one private).
  - Commands: Uses crypto key generate rsa.
  - Purpose: Provides the underlying cryptographic muscle. The router uses its private RSA key to sign IKE/IPsec negotiations or SSH sessions, while the public RSA key is embedded in the device's certificate for peers to verify.

* FQDN
  - An FQDN (Fully Qualified Domain Name) is the complete and exact address for a specific computer, server, or resource on the internet. It specifies every level of the Domain Name System (DNS) hierarchy, leaving no room for doubt about where the resource lives.

* [Configure SSH on Routers](https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-shell-ssh/4145-ssh.html)
