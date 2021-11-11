##! Zeek scripts that are used to detect suspicious data in detected HTTP payloads

# Extend the existing HTTPAppExposure module
module HTTPAppExposure;

export {
        # Apache Server Status signatures are based on two lines in a response page.
        # Example 1: <title>Apache Status</title>
        # Example 2: <h1>Apache Server Status for example.com
        const apache_status_sig: pattern =
                /apache[[:space:]]server[[:space:]]status[[:space:]]for[[:space:]]/i |
                 /\<title\>apache[[:space:]]status\<\/title\>/i &redef;

        ## The detected MIME types we want to observe for the Apache Server Status Page
        const apache_status_observed_mime_types: table[string] of string = {
            ["text/html"] = "html"
        } &redef;
}

function check_apache_status_sigs(c: connection, f: fa_file, data: string): bool {
    local instances = find_all(data, apache_status_sig);

    for (inst in instances) {
        if(c?$http) {
            # This is a processing efficiency tactic here. Return early from the event.
            if((!Site::is_local_addr(c$id$resp_h)) 
                || (!c$http?$status_code) 
                || !(c$http$status_code in HTTPAppExposure::app_success_status_codes)) {
                return F;
            }
    
            # Check for field existence and assign defaults
            local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
            local method = c$http?$method ? c$http$method : "<unknown>";
            local uri = c$http?$uri ? c$http$uri : "<unknown>";
            local respPort = port_to_count(c$id$resp_p);

            NOTICE([$note=Apache_Server_Status_Page_Found,
                    $msg=fmt("Possible Apache Server Status Page (Apache status module) found - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                    $sub=fmt("%s", data),
                    $conn=c,
                    $identifier=cat(c$id$resp_h, uri),
                    $suppress_for=1day]);
            return T;
        }
        return F;
    }
    return F;

}

event HTTPAppExposure::stream_apache_status_data(f: fa_file, data: string) {
    local c: connection;
    for ( id in f$conns ) {
        # Loop until we collect the ID of the connection
        c = f$conns[id];
        break;
    }

    if ( c$start_time > network_time()-10secs ) {
        check_apache_status_sigs(c, f, data);
    }
}


event file_sniff(f: fa_file, meta: fa_metadata) {
    if(! meta?$mime_type) return;
    if(! f?$conns) return;

    if(!(meta$mime_type in HTTPAppExposure::apache_status_observed_mime_types)) return;

    Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=HTTPAppExposure::stream_apache_status_data]);

}

