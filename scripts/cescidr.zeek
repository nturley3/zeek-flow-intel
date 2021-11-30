##! Module is responsible for supporting institutional CIDR
##! range labeling. 

module flow_intel_cescidr;

export {
    # This is the subnet index (first column) of the cescidr intel file
    type cescidr_idx: record {
        subnet_block: subnet;
    };

    # Record to store all values from the cescidr intel file (remaining columns)
    type cescidr_val: record {
        labels: set[string]; # Supports CSV tokenization
    };

    # Defines the table of subnets that are collected from the intel file
    global subnet_table: table[subnet] of cescidr_val = table();

    # The record of fields that will be written to the zeek logs (esp. conn.log) 
    type cescidr_intel_fields: record {
        orig: set[string] &optional &log; 
        resp: set[string] &optional &log; 
    } &redef;

    # Redefine the conn.log and add the new tagging fields
    redef record Conn::Info += {
        ces: cescidr_intel_fields &log &optional;
    };

    # Redefine the http.log and add the new tagging fields
    # NOTE: This code can be removed once Humio supports query joins
    redef record HTTP::Info += {
        ces: cescidr_intel_fields &log &optional;
    };

    # The intel file to read and generate the intel lookup table
    const cescidr_labels_file = "/workspace/datafiles/cescidr.intel" &redef;
}

# This event should be able to fire at any time since we only rely on the
# 4-tuple connection state info and should be available
event connection_state_remove(c: connection) {
    # Label originating campus IP/subnet if found
    if(c$id$orig_h !in Site::private_address_space && c$id$orig_h in subnet_table) {
        if(!c$conn?$ces) {
            c$conn$ces = cescidr_intel_fields();
        }

        c$conn$ces$orig = subnet_table[c$id$orig_h]$labels;

        if(c?$http) {
            if(!c$http?$ces) {
                c$http$ces = cescidr_intel_fields();
            }
            c$http$ces$orig = subnet_table[c$id$orig_h]$labels;
        }
    }

    # Label responding campus IP/subnet if found
    if(c$id$resp_h !in Site::private_address_space && c$id$resp_h in subnet_table) {
        if(!c$conn?$ces) {
            c$conn$ces = cescidr_intel_fields();
        }

        c$conn$ces$resp = subnet_table[c$id$resp_h]$labels;

        if(c?$http) {
            if(!c$http?$ces) {
                c$http$ces = cescidr_intel_fields();
            }
            c$http$ces$resp = subnet_table[c$id$resp_h]$labels;
        }
    }
    return;
}

# Enrich the http.log with CES campus labels
# Default priority in http.zeek is -5
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
    # Label originating campus IP/subnet if found
    if(c$id$orig_h !in Site::private_address_space && c$id$orig_h in subnet_table) {
        if(!c$http?$ces) {
            c$http$ces = cescidr_intel_fields();
        }
        c$http$ces$orig = subnet_table[c$id$orig_h]$labels;
    }

    # Label responding campus IP/subnet if found
    if(c$id$resp_h !in Site::private_address_space && c$id$resp_h in subnet_table) {
        if(!c$http?$ces) {
            c$http$ces = cescidr_intel_fields();
        }
        c$http$ces$resp = subnet_table[c$id$resp_h]$labels;
    }
}

#event Input::end_of_data(name: string, source: string) {
#        # now all data is in the table
#        print fmt("Name: %s, Source: %s", name, source);
#        print(to_json(subnet_table));
#}

event zeek_init() {
    if(cescidr_labels_file != "") {
        Input::add_table([$source=cescidr_labels_file, $name="campus_cidr_labels",
                        $idx=cescidr_idx, $val=cescidr_val, $destination=subnet_table,
                        $mode=Input::REREAD]);
        # https://docs.zeek.org/en/master/frameworks/input.html
        # See note about asynchronous processing and the possibility that on small PCAP files, the input data may not be immediately
        # available by the time the packets have processed. This can cause some problems with unit tests. 
        # We can trigger this a bit earlier by removing the input stream
        # Input::remove("campus_cidr_labels");
    }
}
