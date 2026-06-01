# Cisco Router IPSec Configuration

## Question? what is different about cisco router crypto isakmp policy 1 and 10?

In a Cisco router configuration, the numbers 1 and 10 denote the priority of the ISAKMP policy. There is no difference in capability between the two; they are just labels used to dictate the order in which the router will offer or negotiate its VPN Phase 1 settings.

The Numbers Represent Priority

The number determines the router's preference. The router evaluates them sequentially, starting with the lowest number closest to 1. 
* Priority 1: The router will negotiate this policy first. If the remote peer's settings match crypto isakmp policy 1, the tunnel establishes immediately.
* Priority 10: The router will evaluate this second, only if policy 1 fails to match the remote peer's settings. [

What is usually inside them?

Each policy holds a specific combination of encryption, hashing, authentication, and Diffie-Hellman parameters. For example:
* Policy 1 might be highly secure (e.g., AES-256 encryption, SHA-384 hashing, DH Group 14).
* Policy 10 might be a legacy or fallback policy (e.g., 3DES encryption, MD5 hashing, DH Group 2) for older remote routers.


## Question? cisco router access list 100 meaning

On a Cisco router, an access list (ACL) 100 represents an Extended IP Access List. It is used to filter network traffic based on both source and destination IP addresses, specific protocols (like TCP or UDP), and specific port numbers (like HTTP, DNS, or SSH).

Why ACL 100?

In Cisco's IOS, access lists are assigned specific number ranges to identify their type.

* Standard ACLs (1-99 / 1300-1999): Filter traffic based only on the source IP address.
* Extended ACLs (100-199 / 2000-2699): Allow for granular control, filtering by source IP, destination IP, protocol, and port

## Question? what is the pre-share key when I configurate ipsec in cisco router?

crypto isakmp key [your-secret-password] address [peer-ip-address]

## Question? ISAKMP

ISAKMP (Internet Security Association and Key Management Protocol) is the framework used to establish, negotiate, modify, and delete Security Associations (SAs) and cryptographic keys in IPsec networks. It defines the mechanics of the key exchange, while protocols like IKE (Internet Key Exchange) dictate the actual authentication methods.

Core Concepts

* Phase 1 (ISAKMP SA): Establishes an authenticated, secure, and encrypted communication channel between two peers. This channel is then used to securely negotiate subsequent tunnels.
* Phase 2 (IPsec SA): Negotiates the actual cryptographic parameters and keys used to protect the actual user data traversing the IPsec tunnel.
* Port and Protocol: Operates over UDP port 500.
* IKE vs. ISAKMP: In many configurations (like Cisco), IKE and ISAKMP are used interchangeably. Technically, ISAKMP is the framework, and IKE is the implemented protocol running within that framework.

* [Resource of ISAKMP](https://community.cisco.com/t5/security-knowledge-base/isakmp/ta-p/3113882)

## Question? when configuring crypto isakmp policy in cisco router c8200, I don't have command isakmp. How to fix it?

Activate the security license
```putty
Router(config)# license boot level network-advantage addon dna-advantage
```

## Question? command details of crypto ipsec transform-set

crypto ipsec transform-set [transform-set-name] [Encrpyion transform1] [Authentication transform2].

* transform - Specifies two "transforms". These transforms define the IPSec security protocols and algorithms. Accepted transform values are described in the "transform table".

* Encryption Transform (Confidentiality): This scrambles the actual payload of your data using ciphers like esp-aes. It prevents unauthorized parties from reading the contents of your traffic if it is intercepted.
  
* Authentication Transform (Integrity & Origin): This creates a cryptographic checksum using hash algorithms like esp-sha256-hmac. It ensures that the data was not altered in transit (integrity) and truly came from the trusted VPN peer (origin verification).

* Encapsulating Security Payload (ESP)

* Authentication Header (AH)

* [Resourse](https://techdocs.audiocodes.com/multi-service-business-routers/command-line-interface/version-720/Content/MSBR2_CLI/crypto%20ipsec%20transform%20set.htm)

## Difference isakmp vs ikev2

* Key DifferencesProtocol Type: ISAKMP is an underlying architecture component (RFC 2408). IKEv2 is an all-in-one, next-generation protocol (RFC 7296).
* Tunnel Speed: IKEv1/ISAKMP requires 6 to 9 messages to build a secure tunnel. IKEv2 requires only 4 messages, making connection speeds much faster.
* Mobility Support: ISAKMP does not support shifting networks. IKEv2 supports MOBIKE, allowing users to switch from Wi-Fi to cellular data without dropping the VPN tunnel.
* Bandwidth Usage: IKEv2 uses significantly less bandwidth and overhead than older ISAKMP/IKEv1 frameworks.
* Reliability: IKEv2 uses built-in sequence numbers and acknowledgments. If a message is lost, IKEv2 automatically retransmits it. ISAKMP relies on external mechanisms.
* NAT Traversal: IKEv2 has native support for NAT Traversal (UDP port 4500). ISAKMP requires optional extensions to handle NAT.

## prf algorithm?

The prf (Pseudo-Random Function) command configures the algorithm used by IKEv2 to generate keying material and hashing operations for the IKE SA (Security Association) session.

## Resource

*[Site-to-Site IKEv2 IPSec VPN Implementation](https://community.cisco.com/t5/security-knowledge-base/site-to-site-ikev2-ipsec-vpn-implementation/ta-p/5304831)

*[Configure a LAN-to-LAN IPsec Tunnel Between Two Routers](https://www.cisco.com/c/en/us/support/docs/routers/1700-series-modular-access-routers/71462-rtr-l2l-ipsec-split.html)
