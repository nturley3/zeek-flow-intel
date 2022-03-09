##! This module provides a mechanism for managing and using institutional 
##! knowledge about a monitored environment to make informed observations
##! of normal and abnormal network activity
##!
##! Enable SSL Decrypt flow tagging for http.log

module flow_intel_ssldecrypt;

export 
{
    # This is the subnet index (first column) of the subnets intel file
    type idx: record 
    {
        resp_h: subnet;
    };

    # Record to store all values from the intel file 
    type val: record 
    {
        resp_p: set[port];
        orig_h: set[subnet] &optional;
        decrypt: bool;
        url_category: string &optional;
        profile: string;
        # tags: set[string]; # Supports CSV tokenization
    };

    # Defines the table of subnets that are collected from the intel file
    global ssldecrypt_flowtags: table[subnet] of val;

    # Add the additional flow intel fields
    redef record flow_intel::flow_intel_fields += {
        ssldecrypt_profile: string &log &optional;
        ssldecrypted: bool &log &optional;
    };

    # The intel file to read and generate the state table
    const ssldecrypt_intel_file = "/workspace/datafiles/ssldecrypt.intel" &redef;
}

# http_message_done event must be used to properly catch and label all HTTP requests and replies 
# of a session. Using something like http_stats wont work since the event has already been 
# processed and logged out by the time this event fires
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-3
{
    # If using the new_connection event, c$conn does not work since the conn object has not been constructed yet
    # Only begin matches on originators for now and get out of the event early if no match. 
    if(c$id$resp_h !in Site::local_nets)
    {
        return;
    }

    if(c$id$resp_h in ssldecrypt_flowtags)
    {
        if(|ssldecrypt_flowtags[c$id$resp_h]?$resp_p| == 0
          || (|ssldecrypt_flowtags[c$id$resp_h]?$resp_p| > 0 && c$id$resp_p in ssldecrypt_flowtags[c$id$resp_h]$resp_p)) 
        {
            # Flow has been identified for tagging
            if(!c$http?$ir) {
                c$http$ir = flow_intel::flow_intel_fields();
            }

            # TODO: Remove usage of this bool
            c$http$ir$ssldecrypted = T;
            # TODO: need to get table index key, NOT just resp_h (what happens if match is not a /32)
            c$http$ir$ssldecrypt_profile = ssldecrypt_flowtags[c$id$resp_h]$profile;
            return;
        }
    }
}

event zeek_init() 
{
    if(ssldecrypt_intel_file != "") {
        Input::add_table([$source=ssldecrypt_intel_file, $name="ssldecrypt_flowtags",
                        $idx=idx, $val=val, $destination=ssldecrypt_flowtags,
                        $mode=Input::REREAD]);
        Reporter::info(fmt("Intel Loaded: %s", ssldecrypt_intel_file));
    }
    # Input::remove("ssldecrypt_flowtags");
}