# DNS Sinkhole

## Configure an Internal DNS Sinkhole

* If your Level 3 supervisory networks must resolve names, route them through an internal, highly controlled corporate DNS server. Configure the server with a Sinkhole / Blocklist policy (such as RPZ - Response Policy Zones):
  - How these components work together: Build the sinkhole on a dedicated Server (virtual machine, container, or bare metal), and then use your Switches and Routers to enforce its use. The Server (Where the Sinkhole Lives), The Router or DHCP Server (Where you Route Traffic), and The Switch or Firewall (Where you Secure it)
  - Block Unknown Subdomains: Configure a high-volume query threshold. If a single external domain suddenly receives thousands of unique, random subdomain requests from one internal host, block the domain automatically.
  - Inspect Record Types: Block or alert on an unusual influx of TXT or NULL records, which are rarely used by legitimate applications but are heavily favored by tunneling tools to carry large payloads.
  
## Configuring an RPZ Sinkhole in BIND9 (Enterprise Standard)

* Response Policy Zones (RPZ) allow a BIND DNS server to override standard internet lookups using custom zone files.

* Step 1: Define the RPZ in your configuration file
  - Open your primary configuration file (typically /etc/bind/named.conf.options or named.conf.local) and add an response-policy statement inside the options block:
```
options {
    directory "/var/cache/bind";

    // Enable the Response Policy Zone
    response-policy { zone "rpz.sinkhole"; };
};
```

* Step 2: Declare the Zone File
  - In your named.conf.local file, define where the database for your blocked domains will live:
```
zone "rpz.sinkhole" {
    type master;
    file "/etc/bind/db.rpz.sinkhole";
    allow-query { localhost; };
};
```

* Step 3: Create the Sinkhole Database
  - Create the file /etc/bind/db.rpz.sinkhole and add your custom redirection rules.
```
$TTL 1W
@   IN  SOA localhost. root.localhost. (
        2026081101 ; Serial (YYYYMMDDNN)
        1H         ; Refresh
        15M        ; Retry
        1W         ; Expire
        1W )       ; Minimum
    IN  NS  localhost.

; --- SINKHOLE ENTRIES ---

; Redirect a specific malicious domain to a dead-end internal logging server
malicious-tunnel.com     IN  A   10.10.4.50
*.malicious-tunnel.com   IN  A   10.10.4.50

; Logically block a domain entirely by returning NXDOMAIN (Does Not Exist)
badware.org              IN  CNAME .
*.badware.org            IN  CNAME .
```

* Note: A trailing dot . in a CNAME record tells BIND to return an NXDOMAIN error, dropping the connection completely.
* Step 4: Restart and Test
  - Verify your syntax and restart the service:
```bash
named-checkconf
systemctl restart bind9
```

## Deploying a Pi-hole Sinkhole (Quickest & Easiest)

* If you prefer a web-based GUI with automated blocklists (called "Adlists"), Pi-hole is an excellent choice for staging environments.

* Step 1: Install Pi-hole
  - On a clean Linux machine (Ubuntu/Debian/Raspberry Pi OS), run the official deployment script:
```bash
curl -sSL https://pi-hole.net | bash
```

Follow the on-screen prompts to set a static IP address and select an upstream provider (like Cloudflare or Quad9) for legitimate traffic.

* Step 2: Configure Automatic Threat Feeds

  1. Log into your Pi-hole web admin dashboard (http://<IP_ADDRESS>/admin).
  2. Navigate to Settings \(\rightarrow \) Adlists.
  3. Add the URL of a trusted cybersecurity threat feed containing known DNS tunneling and C2 domains (for example, the Firebog or OISD security lists).
  4. Run a gravity update via the UI or terminal (pihole -g) to pull down all the malicious domains into the database.

* Step 3: Add Custom Local Redirections (Optional)
  - If you want to manually redirect an internal domain to an incident response landing page:
  
  1. Go to Local DNS \(\rightarrow \) DNS Records.
  2. Type in the target domain (e.g., malicious-vendor-link.local).
  3. Enter the local IP address where you want to redirect the traffic.
  4. Click Add.

* Step 4: Route Clients to the Sinkhole
  - For the sinkhole to protect your environment, your network assets must be forced to use it:
  - DHCP Configuration: Update your core switches or router DHCP scopes so that the Primary DNS Server assigned to clients is the exact IP address of your new BIND or Pi-hole server.
  - Firewall Lockout: Configure a firewall rule that blocks any outbound port 53 (UDP/TCP) traffic to the public internet unless it originates from your authorized sinkhole server. This prevents attackers or malicious software from bypassing your sinkhole using hardcoded external DNS servers like 8.8.8.8.
