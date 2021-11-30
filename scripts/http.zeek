# HTTP.zeek 
# https://github.com/zeek/zeek/blob/master/scripts/base/protocols/http/main.zeek 
module flow_intel;

export {
    # Redefine the http.log and add the new tagging fields
    redef record HTTP::Info += {
        ir: flow_intel_fields &log &optional;
    };

}

# Default priority in http.zeek is -5
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
	if(!c$http?$ir) {
		local tidx: addr = 0.0.0.0;
		# Check whether this flow qualifies for tagging
		tidx = flow_intel::flow_qualifies(c);

		if(tidx != 0.0.0.0) {
			# Flow has been identified for tagging
			# Enhance the conn.log
			c$http$ir = flow_intel::build_ir_record(tidx);
		}
		return;
	}
}

# Default priority in http.zeek is -5
event connection_state_remove(c: connection) {
	if(c?$http && !c$http?$ir) {
		local tidx: addr = 0.0.0.0;
		# Check whether this flow qualifies for tagging
		tidx = flow_intel::flow_qualifies(c);

		if(tidx != 0.0.0.0) {
			# Flow has been identified for tagging
			# Enhance the conn.log
			c$http$ir = flow_intel::build_ir_record(tidx);
		}
		return;
	}
}
