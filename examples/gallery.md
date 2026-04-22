## Known Working Scenario Set

These examples are public, text-first proof artifacts derived from donor-backed workflows and aligned with the scenario fixture corpus.

`0.2.1` canonical public set:

- `campus`
- `home_iot`
- `service_heavy`

Hero visual:

- [complex campus screenshot](screenshots/complex_campus_master_edit_v4.png)

| Title | Family | Capabilities | Image | Inventory |
| --- | --- | --- | --- | --- |
| Complex Campus | `campus` | management_vlan, telnet, acl, server_dns, server_email, server_aaa, wireless_mutation | [screenshot](screenshots/complex_campus_master_edit_v4.png) | [manifest](complex_campus_master_edit_v4.inventory.json) |
|  |  | Management VLAN, Telnet, ACL, DNS, email, AAA, and multi-SSID wireless campus edit. |  |  |
|  |  | `known_working_example | donor=donor-backed | capabilities=management_vlan, telnet, acl` |  |  |
|  |  | `campus_core_complex | known_working_example | family=campus` |  |  |
|  |  | `management_vlan=generate-ready, telnet=generate-ready, acl=generate-ready` |  |  |
|  |  | `decision=known_working_example | donor_origin=donor-backed` |  |  |
|  |  | `runtime=donor-backed example artifact` |  |  |
| Home IoT | `home_iot` | iot, iot_registration, wireless_ap | [screenshot](screenshots/home_iot_cli_edit_v1.png) | [manifest](home_iot_cli_edit_v1.inventory.json) |
|  |  | Home gateway and IoT device onboarding with gateway-backed registration state. |  |  |
|  |  | `known_working_example | donor=donor-backed | capabilities=iot, iot_registration, wireless_ap` |  |  |
|  |  | `home_iot_complex | known_working_example | family=home_iot` |  |  |
|  |  | `iot=generate-ready, iot_registration=generate-ready, wireless_ap=generate-ready` |  |  |
|  |  | `decision=known_working_example | donor_origin=donor-backed` |  |  |
|  |  | `runtime=donor-backed example artifact` |  |  |
| Service Heavy | `service_heavy` | server_dns, server_dhcp, server_ftp, server_email, server_syslog, server_aaa | [screenshot](screenshots/service_heavy_cli_edit_v1.png) | [manifest](service_heavy_cli_edit_v1.inventory.json) |
|  |  | Service-rich server lab with DNS, DHCP, FTP, email, syslog, AAA, and detailed service metadata. |  |  |
|  |  | `known_working_example | donor=donor-backed | capabilities=server_dns, server_dhcp, server_ftp` |  |  |
|  |  | `service_heavy_complex | known_working_example | family=service_heavy` |  |  |
|  |  | `server_dns=generate-ready, server_dhcp=generate-ready, server_ftp=generate-ready` |  |  |
|  |  | `decision=known_working_example | donor_origin=donor-backed` |  |  |
|  |  | `runtime=donor-backed example artifact` |  |  |
|  |  | extra visuals: [detail 1](screenshots/service_heavy_cli_edit_v1_dhcp.png); [detail 2](screenshots/service_heavy_cli_edit_v1_dns.png); [detail 3](screenshots/service_heavy_cli_edit_v1_ftp.png) |  |  |

