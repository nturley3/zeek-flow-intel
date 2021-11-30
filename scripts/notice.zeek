module flow_intel;

export {
    # Redefine the notice.log and add the new tagging fields
    redef record Notice::Info += {
        ir: flow_intel_fields &log &optional;
    };
}

# Be sure to use Notice::policy() here and not Notice::notice() hook since we need the 
# 'conn' record to be set. If you use Notice::notice() hook, conn is usually uninitialized
hook Notice::policy(rec: Notice::Info): bool &priority=5 {
    if(!rec?$id) {
        # Reporter::warning(fmt("rec$id was missing in Notice hook: %s", rec));
        return;
    }

    # Make sure the connection record exists
    if(rec?$conn) {
        local tidx: addr = 0.0.0.0;
        local note: string = fmt("%s", rec$note); # Convert Analyzer::Tag enum to string

        # Check whether this flow qualifies for tagging
        tidx = flow_intel::flow_qualifies(rec$conn);

        # Check whether an IP is returned (flow qualifies for tagging) and whether the intel file
        # specifies a specific notice ID to reference
        if(tidx != 0.0.0.0 && subnet_flowtags[tidx]?$notices && note in subnet_flowtags[tidx]$notices) {
            # Build the IR record
            # Enhance the notice log
            rec$ir = flow_intel::build_ir_record(tidx);
        }
    }

    return;
}