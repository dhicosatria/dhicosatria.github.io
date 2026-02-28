# day 13 Holiday Routing

category : Miscellaneous

## **Description**

The elves have been brushing up on their cybersecurity skills, and lately, they’ve taken a liking to CyberPatriot-style network hardening. After a routine workshop in the North Pole’s Network Operations Center, something feels... unfinished.

Your task is to step into the role of a junior NetOps elf and bring order to a small but critical enterprise network. Routers, switches, routing protocols, and access controls all need a careful review. The infrastructure mostly works, but “mostly” isn’t good enough when toy production depends on uptime.

Nothing here is flashy. Nothing here is magical. Just solid, disciplined network configuration, the kind Santa trusts.

[**https://living-shandeigh-idkwtps-3a828bc0.koyeb.app/**](https://living-shandeigh-idkwtps-3a828bc0.koyeb.app/) (temporary link for now; may change soon)

Notes/Corrections:

- It will give you the flag after 85%+ completion
- Use PacketTracer v9.0.0
- Enable the authentication globally for Area 0 under the router ospf process, rather than enabling it on the individual interfaces.
- For the Branch Router OSPF configuration, advertise the LAN networks using a single network statement that covers the entire 192.168.100.0/24 block
- **`Create a Named Extended ACL called 'SECURE_HQ'`** - Apply this ACL outbound on the HQ Router's LAN interface (G0/0/1) to filter traffic as it exits the router toward the Server.
- Configure OSPF to suppress updates on the LAN interface. You must explicitly name the interface.

## **Attachments**

[**adventofctf2025.pka**](https://files.vipin.xyz/api/public/dl/3wXteHBA/Day%2013/adventofctf2025.pka)

[**https://living-shandeigh-idkwtps-3a828bc0.koyeb.app/**](https://living-shandeigh-idkwtps-3a828bc0.koyeb.app/) 

```jsx
#PT aaactivity
Instructions

Do not move cables or change the physical topology.
Do not remove the "ISP" router configurations.
You will not receive a completion flag until you score at least 90%.
1. IP Addressing & Subnetting
Configure the interfaces based on the table below.
Subnetting: You are given the block 192.168.100.0/24 for the Branch LANs.
VLAN 10 (Staff): Assign the first valid /26 subnet. (Gateway is first usable).
VLAN 20 (Guest): Assign the second valid /26 subnet. (Gateway is first usable).
HQ WAN: 10.0.0.0/30 (HQ is .1, ISP is .2)
Branch WAN: 10.0.0.4/30 (Branch is .5, ISP is .6)
2. Switch Security (Layer 2)
Branch-Switch:
VLANs: Create VLAN 10 ("Staff") and VLAN 20 ("Guest").
Trunking: Configure the link to the router (Fa0/1) as a Trunk. Disable DTP (use switchport nonegotiate).
Access Ports:
PC 1 (Fa0/2) -> VLAN 10.
PC 2 (Fa0/3) -> VLAN 20.
Port Security:
Enable Port Security on Fa0/2 and Fa0/3.
Allow a maximum of 1 MAC address.
Configuration type: Sticky.
Violation mode: Restrict.
 Administratively shut down all unused FastEthernet ports.
HQ-Switch:
Ensure the Server connected to Fa0/2 is in VLAN 1 (Default).
Configure the uplink to the router (G0/0/1) as an Access port in VLAN 1.
3. Routing & Connectivity (Layer 3)
OSPF Configuration:
Configure OSPF Process ID 1 on HQ-Router, Branch-Router, and ISP-Router.
Use Area 0 for all networks.
Advertise all directly connected networks.
Security: Configure MD5 Authentication on the WAN links between HQ<->ISP and Branch<->ISP.
Key ID: 1
Key: "Cisc0Rout3s"
Passive Interfaces: Ensure OSPF updates are not sent out to the LAN interfaces (Gigabit ports facing the switches).
4. Access Control Lists (ACLs)
HQ-Router Security:
Create a Named Extended ACL called "SECURE_HQ".
Rules:
Permit HTTP traffic from the Branch VLAN 10 network to the HQ Server.
Permit ICMP (Ping) from the Branch VLAN 10 network to the HQ Server.
Deny all other IP traffic from the Branch VLAN 20 network to the HQ LAN.
Permit all other traffic.
Application: Apply this ACL to the most appropriate interface and direction to filter traffic entering the HQ network.
5. Device Hardening
All Routers:
Set the Enable Secret to "Hard3n3d!"
Create a user "NetOps" with secret "AdminPass"
Configure SSH (Version 2, Domain nexus.corp, 1024 bit key).
Disable ip http server and ip http secure-server.
Check Results:
Submit the flag to the website provided.
```

[adventofctf2025.pka](media/adventofctf2025.pka)

![image.png](media/day13.png)

csd{C1sc0_35_muy_m4l_e290bgk7o5}