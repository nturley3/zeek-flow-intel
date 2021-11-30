# SSH.zeek 
# https://github.com/zeek/zeek/blob/master/scripts/base/protocols/ssh/main.zeek
module flow_intel;

export {
    # Redefine the rdp.log and add the new tagging fields
    redef record SSH::Info += {
        ir: flow_intel_fields &log &optional;
    };
}

# Original priority is -5
# This event is used in ssh.zeek to write out the ssh.log early
# We must also use event to enrich the log prior to the log being written
event ssh_auth_attempted(c: connection, authenticated: bool) {
    if(c?$ssh && !c$ssh?$ir) {
        local tidx: addr = 0.0.0.0;
        # Check whether this flow qualifies for tagging
        tidx = flow_intel::flow_qualifies(c);

        if(tidx != 0.0.0.0) {
            # Flow has been identified for tagging
            # Enhance the conn.log
            c$ssh$ir = flow_intel::build_ir_record(tidx);
        }
        return;
    }
}

# Original priority is -5
# This event is used in ssh.zeek to write out the ssh.log early
# We must also use event to enrich the log prior to the log being written
event ssh_auth_failed(c: connection) {
    if(c?$ssh && !c$ssh?$ir) {
        local tidx: addr = 0.0.0.0;
        # Check whether this flow qualifies for tagging
        tidx = flow_intel::flow_qualifies(c);

        if(tidx != 0.0.0.0) {
            # Flow has been identified for tagging
            # Enhance the conn.log
            c$ssh$ir = flow_intel::build_ir_record(tidx);
        }
        return;
    }
}

event connection_state_remove(c: connection) {
    if(c?$ssh && !c$ssh?$ir) {
        local tidx: addr = 0.0.0.0;
        # Check whether this flow qualifies for tagging
        tidx = flow_intel::flow_qualifies(c);

        if(tidx != 0.0.0.0) {
            # Flow has been identified for tagging
            # Enhance the conn.log
            c$ssh$ir = flow_intel::build_ir_record(tidx);
        }
        return;
    }
}

