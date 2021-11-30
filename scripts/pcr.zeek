module flow_intel;

export {
    # Add the pcr field to the conn.log record
    redef record Conn::Info += {
        pcr: double &log &optional;
    };
}

# Add Producer-Consumer Ratio (PCR) to all connections when the connection state is removed
event connection_state_remove (c: connection) &priority=3 {
    if ( ! c$conn?$orig_bytes && ! c$conn?$resp_bytes ) {
        return;
    }
    else if (c$conn$orig_bytes == 0 && c$conn$resp_bytes == 0 ) {
        c$conn$pcr = 0.0;
    }
    else {
        # Calculate the PCR
        local n = (c$conn$orig_bytes + 0.0) - (c$conn$resp_bytes + 0.0);
        local d = (c$conn$orig_bytes + 0.0) + (c$conn$resp_bytes + 0.0);

        local x = ( n / d );
        c$conn$pcr = x;
    }
}