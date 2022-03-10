##! Module is responsible for supporting IPAM intel federation and
##! enriched the conn.log. Examples of IPAM include QIP, BlueCat. 
module flow_intel_ipam;

export {
    # This is the subnet index (first column) of the ipam intel file
    type ipam_idx: record {
        subnet_block: subnet;
    };

    # Record to store all values from the ipam intel file (remaining columns)
    type ipam_val: record {
        labels: set[string]; # Supports CSV tokenization
    };

    # Defines the table of subnets that are collected from the intel file
    global subnet_table: table[subnet] of ipam_val;

    # The record of fields that will be written to the bro logs (esp. conn.log) 
    type ipam_intel_fields: record {
        orig: set[string] &optional &log; 
        resp: set[string] &optional &log; 
    } &redef;

    # Redefine the conn.log and add the new tagging fields
    redef record Conn::Info += {
        ipam: ipam_intel_fields &log &optional;
    };

    # The intel file to read and generate the intel lookup table
    const ipam_labels_file = "/workspace/datafiles/ipam.intel" &redef;
}

# This event is raised when a data time in the source intel is added, removed or changed in the table
# This will report to the reporter.log and should be used for monitoring Input framework status and debugging
# This should only be enabled for debugging, otherwise it generates a lot of events
# NOTE: For the events below, we leverage reading_live_traffic(). The reason is that on Corelight sensors, attempting to use
# the Reporter framework (e.g. Reporter::info) results in a package validation error stemming from zeek_init() and the packages
# will fail to load. This is a bit of a hack to get around the validation errors, but still allow the intel events to fire on Corelight
# and recorded in reporter.log
event ipam_intel_entry_modified(description: Input::TableDescription, tpe: Input::Event, left: ipam_idx, right: ipam_val) {
    if(reading_live_traffic()) {
        Reporter::info(fmt("Intel modified (%s): %s = %s", tpe, to_json(left), to_json(right)));
    }
}

# This event should be able to fire at any time since we only rely on the
# 4-tuple connection state info and should be available
event connection_state_remove(c: connection) {
    # Label originating IP/subnet if found
    if(c$id$orig_h in Site::local_nets && c$id$orig_h in subnet_table) {
        if(!c$conn?$ipam) {
            c$conn$ipam = ipam_intel_fields();
        }
        c$conn$ipam$orig = subnet_table[c$id$orig_h]$labels;
    }

    # Label responding IP/subnet if found
    if(c$id$resp_h in Site::local_nets && c$id$resp_h in subnet_table) {
        if(!c$conn?$ipam) {
            c$conn$ipam = ipam_intel_fields();
        }
        c$conn$ipam$resp = subnet_table[c$id$resp_h]$labels;
    }

    return;
}

event zeek_init() {
    if(ipam_labels_file != "") {
        Input::add_table([$source=ipam_labels_file, 
                            $name="subnet_labels",
                            $idx=ipam_idx, 
                            $val=ipam_val, 
                            $destination=subnet_table,
                            $mode=Input::REREAD,
                            $ev=ipam_intel_entry_modified]);
    }
}
