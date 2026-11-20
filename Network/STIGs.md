# STIG Study Note

## STIG Automation

* [Automate STIG Checklists on Cisco IOS-XE Device - evaluate-stig tool](https://www.youtube.com/watch?v=-PK7WmkrDSE&t=7s)


## BPDU Guard and Root Guard

• BPDU Guard is **the external security gate at the front desk**. It assumes visitors are civilians (hosts). If a visitor arrives heavily armed with tactical gear (a BPDU), security doesn't ask questions—they lock down the turnstile immediately (err-disable), blocking them from entering entirely.

• Root Guard is **the access control door to the Executive Boardroom**. It expects employees (other switches) to walk through the hallways. However, if a junior employee tries to walk into the boardroom, sit in the CEO's chair, and start barking orders (sending a superior BPDU), Root Guard intercepts them, revokes their badge for that specific meeting room (root-inconsistent), but lets them continue working at their normal desk.

• facing a host (BPDU Guard) or facing a switch (Root Guard).


| Metric  |	BPDU Guard |	Root Guard |
| --- | --- | --- |
| Primary Goal |	Keeps switches off the edge. Prevents loops and rogue network additions by end-users. |	Keeps the Root Bridge in the core. Prevents downstream switches from hijacking control. |
| Port Placement |	Access / Edge ports only (facing PCs, printers, IP phones, servers via PortFast). |	Trunk / Distribution ports only (facing downstream switches or external networks). |
| Are BPDUs Expected? |	No. Seeing a BPDU means a switch or a hacking tool was plugged into a user desk jack. |	Yes. It expects normal STP communication, but filters out specific "unauthorized" claims. |
| Trigger Event |	Receiving any BPDU (superior or inferior). |	Receiving a Superior BPDU (a switch claiming a lower/better Bridge ID or path cost). |
| Action Taken |	Shuts down the port completely into an err-disabled state (interface goes physically dark). |	Places the specific VLAN into a root-inconsistent state (traffic is blocked, but port stays up). |
| Recovery Method |	Requires a manual shutdown / no shutdown or an automated errdisable recovery timer. |	Dynamic Self-Healing. The port automatically recovers the moment the superior BPDUs stop. |

## spanning-tree loopguard default

* The spanning-tree loopguard default command globally enables Spanning Tree Protocol (STP) Loop Guard on a switch's point-to-point ports to prevent Layer 2 loops caused by missing BPDUs.

* How It Works

•	Protects non-designated ports: Monitors ports that rely on incoming Bridge Protocol Data Units (BPDUs) to stay in a non-designated role (such as root and alternate ports).

•	Blocks on BPDU loss: If expected BPDUs stop arriving due to a unidirectional link or software issue, the port moves into a loop-inconsistent (bkn) state instead of transitioning to designated forwarding.

•	Auto-recovers: Once BPDUs resume on the port, Loop Guard automatically clears the inconsistent state and restores normal STP operation.

•	Scope: Applies per VLAN and runs on point-to-point links.

* Configuration & Verification

•	Enable globally:
```text
Switch(config)# spanning-tree loopguard default
```

•	Disable globally:
```text
Switch(config)# no spanning-tree loopguard default
```

•	Disable on a specific interface:
```text
Switch(config-if)# no spanning-tree guard loop
```

•	Verify status: Run show spanning-tree summary to check if Loopguard Default is enabled, or show spanning-tree interface <id> detail to inspect port state and loop guard status.

* Key Caveats

•	Mutual exclusion with Root Guard: A port cannot use both Loop Guard and Root Guard simultaneously; enabling one overrides the other on that port.

•	Modern alternatives: Most users on r/ccnp agree that Loop Guard is less common in modern deployments where RSTP or Bridge Assurance is used. For additional implementation details, see Cisco's STP Loop Guard and UDLD guide or NetworkLessons' Loop Guard walkthrough.

## spanning-tree portfast default

The spanning-tree portfast default command globally enables Spanning Tree Protocol (STP) PortFast on all non-trunking (access) ports on a Cisco switch, allowing them to bypass the standard listening and learning states and move immediately to forwarding.

* How It Works

•	Immediate forwarding: Access ports transition directly from blocking to forwarding upon link-up, saving ~30 seconds of convergence delay so end devices (PCs, IP phones, printers) can get DHCP leases and network access right away.

•	Access ports only: When configured globally, PortFast applies strictly to ports operating in access mode (switchport mode access). It does not affect trunk ports unless explicitly forced per interface (spanning-tree portfast trunk).

•	Loop protection behavior: If a PortFast-enabled port receives a BPDU, it loses its PortFast operational status and reverts to normal STP behavior—unless BPDU Guard is also enabled, which puts the port into err-disabled state.

* Configuration & Verification

•	Enable globally (IOS / IOS-XE):
```text
Switch(config)# spanning-tree portfast default
```
(Note: On Cisco NX-OS, the equivalent global command is spanning-tree port type edge default.)

•	Disable globally:
```text
Switch(config)# no spanning-tree portfast default
```
•	Disable on a specific interface (such as an uplink or port connected to another switch/hub):
```text
Switch(config-if)# spanning-tree portfast disable
```
•	Verify status: Run show spanning-tree summary to confirm PortFast Default is enabled, or show spanning-tree interface <id> portfast to check an individual port.

* Best Practices & Caveats

•	Pair with BPDU Guard: Always pair global PortFast with spanning-tree portfast bpduguard default so that accidentally plugging a switch into an access port shuts the port down instead of risking a temporary loop.

•	Interaction with Loop Guard: Do not enable Loop Guard on PortFast ports. Loop Guard expects continuous BPDUs on inter-switch links, whereas PortFast is meant for edge ports connected to end hosts that never send BPDUs.

## spanning-tree portfast bpduguard default

* The spanning-tree portfast bpduguard default command globally enables Spanning Tree Protocol (STP) BPDU Guard on all PortFast-enabled ports on a Cisco switch, automatically shutting down any edge port that receives a BPDU.

* How It Works

•	Prevents accidental loops: Because PortFast ports skip normal STP listening and learning states, plugging a switch, hub, or looped cable into an access port can immediately trigger a broadcast storm. BPDU Guard catches incoming BPDUs and shuts down the port before a loop forms.

•	Triggers err-disabled: When a PortFast-enabled port receives a BPDU, the switch immediately places the interface into an err-disabled state (effectively shutting it down).

•	Scope: Globally, it only protects ports that are operationally running PortFast (either via spanning-tree portfast default on access ports or spanning-tree portfast on individual interfaces).
Configuration & Verification

•	Enable globally (IOS / IOS-XE):
```text
Switch(config)# spanning-tree portfast bpduguard default
```
(Note: On Cisco NX-OS, the equivalent global command is spanning-tree port type edge bpduguard default.)

•	Disable globally:
```text
Switch(config)# no spanning-tree portfast bpduguard default
```
•	Disable on a specific interface:
```text
Switch(config-if)# spanning-tree bpduguard disable
```
•	Verify status: Run show spanning-tree summary to confirm PortFast BPDU Guard Default is enabled, or show interfaces status err-disabled to check for ports tripped by BPDU Guard.

* Recovery & Best Practices

•	Manual recovery: By default, a port tripped by BPDU Guard stays err-disabled until an administrator disconnects the offending device and bounces the port (shutdown followed by no shutdown).

•	Automatic recovery: You can configure the switch to automatically re-enable tripped ports after a set timer (e.g., 300 seconds) using:
```text
Switch(config)# errdisable recovery cause bpduguard
Switch(config)# errdisable recovery interval 300
```
•	Always pair with PortFast: Enabling BPDU Guard globally does nothing on ports where PortFast is not active, so it is almost always deployed alongside spanning-tree portfast default.

## errdisable recovery cause bpduguard

The errdisable recovery cause bpduguard command configures a switch to automatically re-enable an interface placed in the err-disabled state by BPDU Guard after a set recovery interval. By default, automatic recovery is disabled, requiring manual shutdown and no shutdown commands unless enabled.

* Configuration & Verification

•	Enable BPDU Guard recovery: Run errdisable recovery cause bpduguard in global configuration mode.

•	Adjust recovery timer (optional): Run errdisable recovery interval <30–86400> in global configuration mode (default is 300 seconds / 5 minutes).

•	Verify status and timers: Run show errdisable recovery in privileged EXEC mode to check if bpduguard is enabled, view the current timer interval, and see interfaces queued for recovery.

* Operational Considerations

•	Repeated violations: If BPDUs are still arriving when the timer expires, the switch brings the port up and immediately puts it back into err-disabled.

•	Security & troubleshooting: Opinions on Reddit are mixed regarding automatic recovery—some administrators appreciate automated restoration on access ports, while others prefer keeping ports down manually in security-sensitive environments until rogue switches or cabling mistakes are investigated. For permanent switch-to-switch links, remove PortFast/BPDU Guard on the port rather than relying on auto-recovery.

## errdisable recovery cause storm-control

The global command to automatically recover ports disabled by storm control is errdisable recovery cause storm-control.
However, storm control thresholds and actions themselves cannot be enabled globally—they must be configured on individual interfaces (or via interface range).

* Global Recovery Configuration

Run this in global configuration mode (config t) to let the switch automatically re-enable ports that were shut down due to a traffic storm:

•	Enable auto-recovery: errdisable recovery cause storm-control

•	Set recovery timer (optional): errdisable recovery interval <30–86400> (default is 300 seconds)

•	Verify: show errdisable recovery

* Interface Storm Control Configuration
* 
Because errdisable recovery cause storm-control only takes effect if an interface is configured to shut down during a storm, you must pair it with interface-level commands:

•	Set traffic thresholds: storm-control {broadcast | multicast | unicast} level <rising> [falling] (configured by bandwidth percentage, bps, or pps depending on platform)

•	Set shutdown action: storm-control action shutdown (by default, storm control only drops excess traffic without putting the port into err-disabled)

For additional configuration details, refer to the Cisco Storm Control Configuration Guide.

## ip dhcp snooping

There is no global ip verify source command on Cisco switches. IP Source Guard can only be enabled at the interface level (ip verify source).

* What Must Be Configured Globally Instead

To make ip verify source function on your access ports, you must first enable its underlying database—DHCP Snooping—in global configuration mode:

•	Enable DHCP Snooping globally: ip dhcp snooping

•	Enable DHCP Snooping on target VLANs: ip dhcp snooping vlan <vlan-id-or-range>

•	Disable Option 82 insertion (usually required on standalone access switches): no ip dhcp snooping information option

* Optional: Static IP Bindings (Global)

If you have hosts with static IP addresses that do not use DHCP, you must manually add their bindings globally so ip verify source does not block their traffic:

•	Static binding syntax: ip source binding <mac-address> vlan <vlan-id> <ip-address> interface <interface-id>

* Interface-Level Commands Required

Once the global prerequisites above are in place, apply the feature per interface (or using interface range):

•	Untrusted access ports: ip verify source (or ip verify source port-security to filter by both IP and MAC)

•	Uplink / DHCP server ports: ip dhcp snooping trust (do not put ip verify source on trusted uplinks)

For platform-specific syntax and verification commands, refer to the Cisco IP Source Guard Configuration Guide.


