# Flow Intelligence Zeek/Corelight Package
Zeek/Corelight package to support flow intelligence using institutional knowledge. The package adds new features and important flow log tagging for integrating institutional data sets such as CMDB, IPAM etc. 

## Overview

This package provides a mechanism for loading institutional knowledge about a monitored environment into Zeek and Corelight leveraging Zeek's input framework. This data is then used to enrich the flow logs (e.g. conn.log) by adding new fields to these logs to be used in a log analytics systems (such as Humio, ELK etc).

Examples of this data enrichment include:

* Adding known system data classifications labels (e.g. Highly Confidential) to events
* Providing the type of system (production, test, development)
* Adding IT or other Point-of-Contact information to alerts
* Adding subnet labels/descriptions or VLAN names to events
* Recording list of known network or vulnerability scanners
* Any other information that can be used from a CMDB, IPAM or other database

## Intelligence Support

Multiple flow intelligence sources are supported by this package and more is being added. 

### IR Flow Intel (flow.intel)

Logs Tagged: `conn.log`, `http.log`, `rdp.log`, `ssh.log`, `notice.log`

This file adds Incident Response intelligence to multiple Zeek/Corelight logs such as conn.log or rdp.log. The intent is for analysts to tag traffic flows that our known (such as known vulnerability scanners or network scanners) and allows analysts to tune alerts accordingly. Each log is enriched with a new `ir.*` log record. 

| Field Name | Data Type |  Description |
| ----- | ----- | ----- |
| ir.id | `set[string]` | IR ticket ID associated with this traffic |
| ir.known | `bool` | Identified whether this flow is known in our IR systems (e.g. known approved scanner) |
| ir.tags | `set[string]` | A list of comma-separated arbitrary string tags (e.g. scanner,telnet,shc) |
| ir.alert_name | `set[string]` | A comma-separated list of unique alert names to identify this alert |

This flow intelligence source supports the following use cases for tagging:

1. Source IP/Subnets + Destination IP/Subnet + Destination Ports (SRC + DST + DPORTS)
1. Source IP/Subnets + Destination IP/Subnets (SRC + DST)
1. SourceIP/Subnets (SRC)
1. Destination IP/Subnets + Destination Ports (DST + DPORTS)
1. Destination IP/Subnets (DST)
1. Source IP/Subnets + Destination Ports (SRC + DPORT)

NOTE: Use cases not in this list are not supported in the intel file

When updating the flow.intel file, it's important to understand the columns in this tab-delimited (TSV) file.

| Column Name | Data Type | Optional | Description |
| ----- | ----- | ----- | ----- |
| subnet_begin | `subnet` | No | The originating subnet for the traffic |
| subnet_end | `set[subnet]` | Yes | A comma-separated list of target subnets for the traffic |
| resp_p | `set[port]` | Yes | The responding ports identified in the traffic flows |
| tag_as_orig | `bool` | No | Used to "flip" the logic. If tagging flows where the destination subnets are only known (source is not known), you set this value to `F` which tells the package to tag any traffic with this subnet/IP as the destination instead of the source. |
| tags | `set[string]` | Yes | A comma-separated list of arbitrary single word string tags (e.g. scanner,telnet,shc) |
| resilient_id | `set[string]` | Yes | A comma-separated list of Resilient incident IDs that are associated with this traffic flow |
| alert_name | `set[string]` | Yes | A comma-separated list of unique alert names |
| notices | `set[string]` | Yes | A comma-separated list of Notice IDs associated with this traffic flow |
| notes | `set[string]` | Yes | A comma-separated list of notes (word, sentences etc). Intended to help communicate more information about this flow but is not included in the actual Zeek/Corelight logs |

**IMPORTANT:** The package is configured to support both subnets and individual IPs for the subnet start and end fields. However, the package uses the `subnet` Zeek data type to do this. While CIDR notation is allowed (e.g. 128.187.10.0/24), individual IPs must also be identified in CIDR notation (e.g. 128.187.12.24/32). If you try to put a single IP in without CIDR notation, Zeek/Corelight will alert on this issue and refuse to process the corresponding line in the intel file. 

### SSL Decryption/Inspection Intel (ssldecrypt.intel)

Logs Tagged: `http.log`

This file adds intelligence that identifies when HTTP flows from a firewall or other device have been inspected/decrypted and sent to Zeek/Corelight. This enables analysts to know when they're dealing with an SSL decrypted flow and to respond accordingly. The http.log is enriched with an updated `ir.*` log record.  

| Field Name | Data Type |  Description |
| ----- | ----- | ----- |
| ir.ssldecrypt_profile | `string` | The SSL decryption profile name from the firewall or other device |
| ir.ssldecrypted | `bool` | Boolean value indicating that this flow has been SSL decrypted |

Below is the list of columns used in the ssldecrypt.intel file.

| Column Name | Data Type | Optional | Description |
| ----- | ----- | ----- | ----- |
| resp_h | `subnet` | No | The single responding IP or subnet that is being SSL decrypted via a firewall or other device |
| resp_p | `set[port]` | Yes | A comma-separated list of web responding ports that are being SSL decrypted (most cases will be 443/tcp) |
| orig_h | `set[subnet]` | Yes | A comma-separated list of originating IPs or subnets that are specific to the SSL decrypt flow. In most cases, we want to tag all SSL decrypted traffic to the destinations, so this column is not used. It is available in the event specific originators and responders need to be tagged. |
| decrypt | `bool` | Yes | Indicates that this flow has been SSL decrypted. (Will be removed in future code since a line in the intel file already indicates the flow is being decrypted) |  
| url_category | `string` | Yes | The URLs being decrypted as configured on the Palo Alto. This is a convenience field to help analysts know what URLs are involved. | 
| profile | `string` | No | The name of the SSL decryption profile as configured on the Palo Alto firewall |

**IMPORTANT:** The package is configured to support both subnets and individual IPs for the subnet start and end fields. However, the package uses the `subnet` Zeek data type to do this. While CIDR notation is allowed (e.g. 128.187.10.0/24), individual IPs must also be identified in CIDR notation (e.g. 128.187.12.24/32). If you try to put a single IP in without CIDR notation, Zeek/Corelight will alert on this issue and refuse to process the corresponding line in the intel file. 

### IP Address Management (IPAM) Intel (ipam.intel)

Logs Tagged: `conn.log`

This file adds intelligence that labels a connection flow with the originating and responding subnet IDs/names identified in the institutions IPAM/DNS system. The conn.log is enriched with a new `ipam.*` record.

| Field Name | Data Type |  Description |
| ----- | ----- | ----- |
| ipam.orig | `set[string]` | The label of the originating subnet/IP |
| ipam.resp | `set[string]` | The label of the responding subnet/IP |

Below is the list of columns used in the ipam.intel file.

| Column Name | Data Type | Optional | Description |
| ----- | ----- | ----- | ----- |
| subnet_block | `subnet` | No | The source/destination subnet block from the IPAM record |
| labels | `set[string]` | No | The identifier or label for this subnet/IP |

**IMPORTANT:** The package is configured to support both subnets and individual IPs for the `subnet_block` field. However, the package uses the `subnet` Zeek data type to do this. While CIDR notation is allowed (e.g. 128.187.10.0/24), individual IPs must also be identified in CIDR notation (e.g. 128.187.12.24/32). If you try to put a single IP in without CIDR notation, Zeek/Corelight will alert on this issue and refuse to process the corresponding line in the intel file. 

### Institution CIDR Intel (cescidr.intel)

Logs Tagged: `conn.log`

This file adds intelligence that labels a connection flow with the originating and responding institution names (e.g. BYU) derived from the IP address (public CIDR blocks of each institution).

| Field Name | Data Type |  Description |
| ----- | ----- | ----- |
| ces.orig | `set[string]` | The label of the originating institution |
| ces.resp | `set[string]` | The label of the responding institution |

Below is the list of columns used in the cescidr.intel file.

| Column Name | Data Type | Optional | Description |
| ----- | ----- | ----- | ----- |
| subnet_block | `subnet` | No | The source/destination subnet block for the institution |
| labels | `set[string]` | No | The identifier or label for this campus |

**IMPORTANT:** The package is configured to support both subnets and individual IPs for the `subnet_block` field. However, the package uses the `subnet` Zeek data type to do this. While CIDR notation is allowed (e.g. 128.187.10.0/24), individual IPs must also be identified in CIDR notation (e.g. 128.187.12.24/32). If you try to put a single IP in without CIDR notation, Zeek/Corelight will alert on this issue and refuse to process the corresponding line in the intel file. 

### CMDB Intel (cmdb.intel)

*Currently in development*

### MAC and VLAN ID Intel

*Currently in development*
