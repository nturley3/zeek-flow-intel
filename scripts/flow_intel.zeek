##! This module provides a mechanism for managing and using institutional 
##! knowledge about a monitored environment to make informed observations
##! of normal and abnormal network activity

##! Intel tagging conditions
##! 1. Source IP/Subnets + Destination IP/Subnet + Destination Ports (SRC + DST + DPORTS)
##! 2. Source IP/Subnets + Destination IP/Subnets (SRC + DST)
##! 3. SourceIP/Subnets (SRC)
##! 4. Destination IP/Subnets + Destination Ports (DST + DPORTS)
##! 5. Destination IP/Subnets (DST)
##! 6. Source IP/Subnets + Destination Ports (SRC + DPORT)
##! Use cases not in this list are not supported in the intel file

module flow_intel;

export {
    # This is the subnet index (first column) of the flow intel file
    type idx: record {
        subnet_begin: subnet;
    };

    # Record to store all values from the intel file (remaining columns)
    type val: record {
        tags: set[string]; # Supports CSV tokenization
        resilient_id: set[int]; # Support multiple tickets (ints)
        subnet_end: set[subnet];
        resp_p: set[port];
        tag_as_orig: bool &default=T;
        alert_name: set[string];
        notices: set[string] &optional;
        hostnames: set[string] &optional; # Hostnames connected to the subnet_begin address (if /32)
        notes: set[string] &optional;
        # resilient_open: bool; # Left for future support
    };

    # Defines the table of subnets that are collected from the intel file
    global subnet_flowtags: table[subnet] of val;

    # The record of fields that will be written to the bro logs (esp. conn.log) 
    # Any fields from the original intel file that need to be recorded in the logs should be added to this record
    type flow_intel_fields: record {
        id: set[int] &optional &log; # Resilient IDs
        tags: set[string] &optional &log; # Any arbitrary tags for a flow
        known: bool &optional &log; # Whether this flow is known in our IR (e.g. known, approved scanner)
        alert_name: set[string] &optional &log; # A unique name for this alert
        # open: bool &optional &log; # Left for future support to show whether the Resilient ticket is open or not
    } &redef;

    # Redefine the conn.log and add the new tagging fields
    redef record Conn::Info += {
        ir: flow_intel_fields &log &optional;
    };

    # The intel file to read and generate the intel lookup table
    const subnet_flow_tagging_file = "/workspace/datafiles/flow.intel" &redef;

    # Event signature for when an intel entry is modified in the file (left here for future support)
    global intel_entry_modified: event(description: Input::TableDescription, tpe: Input::Event, left: idx, right: val);

    # This set of Analyzer::Tags (enum) is used to determine what logs we want to enhance with intel when
    # the corresponding analyzer is detected. 
    # Warning: If you update this set with a new analyzer, you must redefine the corresponding log record (see above)
    # and update the protocol_confirmation event.
#    global check_analyzers: set[Analyzer::Tag] = {
#        Analyzer::ANALYZER_SSL,
#        Analyzer::ANALYZER_RDP,
#    } &redef; 
}

# This event is raised when a data time in the source intel is added, removed or changed in the table
# This will report to the reporter.log and should be used for monitoring Input framework status and debugging
# This should only be enabled for debugging, otherwise it generates a lot of events
 event intel_entry_modified(description: Input::TableDescription, tpe: Input::Event, left: idx, right: val) 
 {
     Reporter::info(fmt("Intel Modified (%s): %s = %s", tpe, left, right));
 }

# Function determines whether the flow (using the 5-tuple connection ID) meets the necessary tagging conditions
# and is found in the intel file
function flow_qualifies(c: connection): addr {
    # If using the new_connection event, c$conn does not work since the conn object has not been constructed yet
    # Only begin matches on originators for now and get out of the event early if no match. 
    if(c$id$orig_h !in Site::local_nets) {
        return 0.0.0.0;
    }

    # Return early if neither side is in the table
    if(c$id$orig_h !in subnet_flowtags && c$id$resp_h !in subnet_flowtags) {
        return 0.0.0.0;
    }

    # Check whether the originator AND responders are in the subnet table
    # if the originator is in the table AND a subnet_end is defined AND the responder is in the subnet_end = tag
    # OR if the originator is in the table AND a subnet_end is not defined AND we should tag the traffic from the originator standpoint = tag
	if ((c$id$orig_h in subnet_flowtags && |subnet_flowtags[c$id$orig_h]$subnet_end| > 0 && 
          c$id$resp_h in subnet_flowtags[c$id$orig_h]$subnet_end)
          || c$id$orig_h in subnet_flowtags && |subnet_flowtags[c$id$orig_h]$subnet_end| == 0 && 
          subnet_flowtags[c$id$orig_h]$tag_as_orig) {
        # Second check whether a response port is in the table and if so, does the port match? Otherwise
        # if the response port is null, tag the flow and ignore any port matching. 
        if(|subnet_flowtags[c$id$orig_h]$resp_p| == 0 
          || (|subnet_flowtags[c$id$orig_h]$resp_p| > 0 && c$id$resp_p in subnet_flowtags[c$id$orig_h]$resp_p)) {
            # Condition #1, #2, #3, #6
            return c$id$orig_h;
        }
	}
    # if the responder is in the subnet table AND a subnet_end is not defined AND we should tag the traffic from the responder standpoint = tag
    # Important to remember here that if tag_as_orig == F, then the subnet_end field must be null
    else if(c$id$resp_h in subnet_flowtags && |subnet_flowtags[c$id$resp_h]$subnet_end| == 0 && 
             !subnet_flowtags[c$id$resp_h]$tag_as_orig) { 
        # Second check whether a response port is in the table and if so, does the port match? Otherwise
        # if the response port is null, tag the flow and ignore any port matching. 
        if(|subnet_flowtags[c$id$resp_h]$resp_p| == 0 
          || (|subnet_flowtags[c$id$resp_h]$resp_p| > 0 && c$id$resp_p in subnet_flowtags[c$id$resp_h]$resp_p)) {
            # Condition #4, #5
            return c$id$resp_h;
        }
    }
    else {
        return 0.0.0.0;
    }
    return 0.0.0.0;
}

function build_ir_record(tidx: addr): flow_intel_fields {
    local ir_tags = flow_intel_fields();

    ir_tags$known = T;
    ir_tags$tags = subnet_flowtags[tidx]$tags;
    ir_tags$alert_name = subnet_flowtags[tidx]$alert_name;
    if(subnet_flowtags[tidx]?$resilient_id) {
        ir_tags$id = subnet_flowtags[tidx]$resilient_id;
    }
    # ir_tags$open = subnet_flowtags[c$id$orig_h]$resilient_open; # Left for future work
    return ir_tags;
}

# Refer to the Zeek documentation on connection_state_remove. We use this event to enhance
# the conn.log once the connection is removed from memory
event connection_state_remove(c: connection) {
    local tidx: addr = 0.0.0.0;
    # Check whether this flow qualifies for tagging
    tidx = flow_intel::flow_qualifies(c);

    if(tidx != 0.0.0.0) {
        # Flow has been identified for tagging
        # Enhance the conn.log
        c$conn$ir = flow_intel::build_ir_record(tidx);
    }
    return;
}

# This event is used to determine when a protocol has been confirmed and whether the corresponding
# protocol log needs to be enhanced. We influence priority here since the labeling of the log may 
# occur after the log has been written. Increase the priority. 

# TODO: Turns out this event is not going to work since the protocol analyzer kicks off at different
# times for different protocols (e.g. HTTP). So while RDP works, HTTP does not since the c$http object
# is not initialized by the time this event fires
#event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=10 {
#    local tidx: addr = 0.0.0.0;
#    # Check whether this flow qualifies for tagging
#    tidx = flow_qualifies(c);
#
#    if(tidx != 0.0.0.0) {
#        # Check if we care about this analyzer
#        if(atype in check_analyzers)
#        {
#            # Flow has been identified for tagging
#            local ir_tags = flow_intel_fields();
#
#            ir_tags$known = T;
#            ir_tags$tags = subnet_flowtags[tidx]$tags;
#            ir_tags$alert_name = subnet_flowtags[tidx]$alert_name;
#            # ir_tags$open = subnet_flowtags[c$id$orig_h]$resilient_open; # Left for future work
#
#            # Enhance the various protocol logs
#            switch(atype) {
#                case Analyzer::ANALYZER_SSL:
#                    c$ssl$ir = ir_tags;
#                    break;
#                case Analyzer::ANALYZER_RDP:
#                    c$rdp$ir = ir_tags;
#                    break;
#                default:
#                    Reporter::warning(fmt("Invalid protocol requested on flow label check: %s", atype));
#                    break;
#            }
#        }
#    }
#    return;
#}

event zeek_init() {
    if(subnet_flow_tagging_file != "") {
        Input::add_table([$source=subnet_flow_tagging_file, $name="subnet_flowtags",
                        $idx=idx, $val=val, $destination=subnet_flowtags,
                        $mode=Input::REREAD]);
        Reporter::info(fmt("Intel Loaded: %s", subnet_flow_tagging_file));
    }
    # Input::remove("subnet_flowtags");
}
