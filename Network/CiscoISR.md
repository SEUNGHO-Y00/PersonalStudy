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

## Command Line

* Create Host Port Maapings no Cisc
```
CiscoISR(config)# ip host Arista-Switch <IP Address>
```

* Use an Interface VLAN
```
CiscoISR(Config)# interface vlan 100
CiscoISR(Config-if)# ip address <ip address> <subnet>

CiscoISR(Config)# interface gi 0/1/0
CiscoISR(Config-if)# switchport mode access
CiscoISR(Config-if)# swtichport access vlan 100
```

* Complete Arista Interface
```
Arista(Config)# Interface Management 1
Arista(Config-if)# vrf MGMT
Arista(Config-if)# ip address <IP Addess>
Arista(Config)# ip route vrf MGMT 0.0.0.0/0 <CiscoISR IP Address>
```

* Verify the connection
```
CiscoISR# ping <Arista IP Address>

Arista# ping vrf MGMT <CiscoISR IP Address>
```

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

* Domain Control
  - Cisco routers running IOS-XE legally refuse to generate cryptographic RSA keys without a domain name.
  - CiscoIRS# ip domain-name company.local
  - Arista# dns domain company.local

* Force Cisco to Use the Management Interface for SSH
```
CiscoISR(config)# ip ssh source-interface Vlan100
```

## Crypto

* Arista Crypto
  - On Arista switches running modern EOS software builds, the crypto key commands are completely missing because the switch automatically generates its own 2048-bit RSA and ECDSA host keys out of the box.
 
* Mordern key exchange standard
  - The Current Industry Standards
  - Curve25519 (ECDH-X25519)
    - What it is: Elliptic-Curve Diffie-Hellman using the Curve25519 architecture.
    - Why it is preferred: It is the current global gold standard for OpenSSH and Arista EOS. It provides maximum security speed, requires significantly less CPU overhead, and is naturally resilient to timing side-channel attacks.
  - ECDH NIST P-256 / P-384
    - What it is: Elliptic-Curve Diffie-Hellman using standard curves approved by the National Institute of Standards and Technology (NIST).
    - Why it is preferred: Broadly required across government and military enclaves (such as networks handling your TACLANEs).
  - Diffie-Hellman Group 14, 15, or 16 with SHA-256/512
    - What it is: Traditional Finite Field key exchanges using highly robust modulus bit spaces (Group 14 is 2048-bit, Group 15 is 3072-bit, and Group 16 is 4096-bit).
    - Why it is preferred: Actively used as a safe fallback when connecting legacy infrastructure (like older Cisco routers) to next-generation environments.
   
* Update the Cisco SSH Client Cryptography
  - A modern key exchange (KEX) standard is a secure mathematical protocol that allows two separate devices—like your Cisco router and your Arista switch—to safely agree on a shared encryption key over an insecure cable connection.
    - What it does: Allows the two devices to securely create a temporary shared session key over an unencrypted network cable.
  - Publickey is the configuration instruction used to define the digital signature algorithms your Cisco router's SSH client is allowed to use when verifying the identity of a remote server. For Privacy (Confidentiality).
    - What it does: Cryptographically verifies the identity of the remote switch and the user trying to log in.
  - Encryption is the specific instruction you type into a Cisco router to define the symmetric encryption ciphers its outbound SSH client is allowed to use. For Identity (Authentication).
    - What it does: Takes readable text strings (like your password or configuration commands) and scrambles them into unreadable noise using the session key generated during the KEX step.
  - "MAC" means Message Authentication Code (the cryptographic hashing algorithm used to prove that packets haven't been tampered with mid-transit).
    - What it does: Acts as a digital cryptographic checksum applied to every single data packet sent across the wire.

 1. KEX (Key Exchange) "Let's create a secret key without emailing it."
 2. PUBLICKEY "Are you the real Arista Switch? Here is my ID."
 3. ENCRYPTION "Scramble all the text we send back and forth."
 4. MAC (Data Integrity) "Make sure nobody alters our commands in transit."

```
CiscoISR(config)# ip ssh client algorithm kex <Best> <Backup>
CiscoISR(config)# ip ssh client algorithm publickey <Best> <Backup>
CiscoISR(config)# ip ssh client algorithm encryption <Best> <Backup>
CiscoISR(config)# ip ssh client algorithm mac <Best> <Backup>
```
