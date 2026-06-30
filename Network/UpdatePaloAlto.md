# Manual Update Palo Alto

1. Update Dynamic Updates
2. Antivirus Updates
3. Software Updates

## Dynamic Updates

* In Palo Alto Networks, encfilesize stands for Encrypted File Size. It is an internal system variable the firewall uses during a content package installation to measure the exact byte size of the encrypted Threat Prevention data payload.

* Lincense Check
  - request license info

* Difference Application and threats vs applications-only? The core difference between these two packages is encryption and threat signatures. Palo Alto distributes them differently based on whether a firewall has a paid security subscription.

* Applications and Threats
  - What it includes: Contains both App-ID (rules to identify applications like Zoom or BitTorrent) AND Threat Signatures (vulnerability exploits, spyware, and anti-virus profiles).
  - Encryption: Fully Encrypted. The threat database contains proprietary intelligence that requires an active cryptographic key to unlock.

*  Applications-Only
  - What it includes: Contains App-ID only. It has zero vulnerability, spyware, or anti-virus signatures.
  - Encryption: Unencrypted / Open. Because application definitions are not restricted security intelligence, the package file does not require cryptographic authorization to unpack.

* What is the content version in palo alto? In Palo Alto Networks, a Content Version is a database update package that continually equips your next-generation firewall with the latest security intelligence. Unlike a PAN-OS software upgrade (which updates the base operating system), a content update modifies firewall signatures without requiring a system reboot or configuration change.

* Resource
  - [Content Update Issue](https://live.paloaltonetworks.com/t5/general-topics/content-update-issue/td-p/355820)

## PAN-OS Upgrade Guide

* Resource
  - [Upgrade a Standalone Firewall](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-upgrade/upgrade-pan-os/upgrade-the-firewall-pan-os/upgrade-a-standalone-firewall#ida2c33421-86f0-4398-9cb7-1287f81c17fe)
  - [Determine the Upgrade Path to PAN-OS 10.2](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-upgrade/upgrade-pan-os/upgrade-the-firewall-pan-os/determine-the-upgrade-path#id85bdf6f4-2e83-49f0-8525-3eb2163f2d2e)
  - [Unable to manually upload dynamic content](https://live.paloaltonetworks.com/t5/general-topics/unable-to-manually-upload-dynamic-content/td-p/1324)
