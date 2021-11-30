@load base/frameworks/notice

module PCI;

export {

    redef enum Notice::Type += {
      Inventory_Violation_MAC
    };

    # This is the subnet index (first column) of the flow intel file
    type vlan_idx: record {
        vlan: int;
    };

    # Record to store all values from the intel file (remaining columns)
    type vlan_values: record {
        inner_vlans: set[int]; # CSV tokenization
        tags: set[string]; # CSV tokenization
        bldg: string;
    };

    # This is the subnet index (first column) of the flow intel file
    type mac_idx: record {
        mac: string;
    };

    # Record to store all values from the intel file (remaining columns)
    type mac_values: record {
        tags: set[string]; # CSV tokenization
    };

    # Defines the table of subnets that are collected from the intel file
    global pci_zones_table: table[int] of vlan_values;
    global pci_macs_table: table[string] of mac_values;

    # The record of fields that will be written to the bro logs (esp. conn.log) 
    type pci_intel_fields: record {
        known: bool &optional &log; # Whether this flow is known in our IR (e.g. known, approved scanner)
    } &redef;

    # Redefine the conn.log and add the new tagging fields
    redef record Conn::Info += {
        pci: pci_intel_fields &log &optional;
    };

    # The intel file to read and generate the intel lookup table
    const pci_zones_file = "/workspace/datafiles/pcizones.intel" &redef;
    const pci_macs_file = "/workspace/datafiles/pcimacs.intel" &redef;
}

function gen_notice(c: connection, note: Notice::Type, msg: string, sub: string)
{
    NOTICE([$note=note,
            $msg=fmt("%s", msg),
            $sub=fmt("%s", sub),
            $conn=c,
            $identifier=cat(c$conn$orig_l2_addr, c$conn$resp_l2_addr),
            $suppress_for=1day]);
}

# Set priority here since mac-logging script is at priority=0 and L2 address fields need to be available
event connection_state_remove(c: connection) &priority=-5 {

  if (!c?$vlan) { return; };
  if (!c?$inner_vlan) { return; };
  local note: string;

  if(c$vlan in pci_zones_table && c$inner_vlan in pci_zones_table[c$vlan]$inner_vlans) {

    if(c$conn$orig_l2_addr !in pci_macs_table || c$conn$resp_l2_addr !in pci_macs_table) {
      gen_notice(c, Inventory_Violation_MAC, "Detected Layer-2 address not found in PCI inventory", fmt("%s (VLAN %d, INNER VLAN %d, BLDG: %s)", c$conn$orig_l2_addr, c$vlan, c$inner_vlan, pci_zones_table[c$vlan]$bldg));
    }

  }
}

event zeek_init() {
    if(pci_zones_file != "") {
        Input::add_table([$source=pci_zones_file, $name="pci_zones",
                        $idx=vlan_idx, $val=vlan_values, $destination=pci_zones_table,
                        $mode=Input::REREAD]);
    }

    if(pci_macs_file != "") {
        Input::add_table([$source=pci_macs_file, $name="pci_macs",
                        $idx=mac_idx, $val=mac_values, $destination=pci_macs_table,
                        $mode=Input::REREAD]);
    }
}