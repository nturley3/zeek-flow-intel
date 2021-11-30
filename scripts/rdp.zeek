# RDP.zeek logs in connection_state_remove() and protocol_violation()
# https://github.com/zeek/zeek/blob/master/scripts/base/protocols/rdp/main.zeek
module flow_intel;

export {
    # Redefine the rdp.log and add the new tagging fields
    redef record RDP::Info += {
        ir: flow_intel_fields &log &optional;
    };
}

# May need logging in the future
#event protocol_violation(c: connection, atype: Analyzer::Tag, aid: count, reason: string) &priority=5 {
#}


# Default priority in rdp.zeek is -5
event connection_state_remove(c: connection) {
    if(c?$rdp && !c$rdp?$ir) {
        local tidx: addr = 0.0.0.0;
        # Check whether this flow qualifies for tagging
        tidx = flow_intel::flow_qualifies(c);

        if(tidx != 0.0.0.0) {
            # Flow has been identified for tagging
            # Enhance the conn.log
            c$rdp$ir = flow_intel::build_ir_record(tidx);
        }
        return;
    }
}