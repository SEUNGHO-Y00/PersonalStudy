# STIG Study Note

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
