##! Bro scripts that are used to detect suspicious data in detected HTTP payloads

# Extend the existing HTTPAppExposure module
module HTTPAppExposure;

export {
        # PCRE sample: /pass(?:word)?\s?[=:]\s?["']?.*/
        # Look for common patterns in INI, JSON, CSV files etc
        const app_credential_sig: pattern = /password[[:space:]]?=[[:space:]]?.*/i | 
                                   /["']password["'][[:space:]]?:[[:space:]]?['"].*['"]/i | 
                                   /password[[:space:]]?:[[:space:]]?['].*[']/i | 
                                   /,password,.*/i &redef;

        ## The detected MIME types we want to observe in credential leakage
        const cred_observed_mime_types: table[string] of string = {
            ["text/plain"] = "txt",
            ["text/ini"] = "ini",
            ["text/inf"] = "inf",
            ["text/json"] = "json",
        } &redef;
}

function check_cred_sigs(c: connection, f: fa_file, data: string): bool {
    local instances = find_all(data, app_credential_sig);

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

            NOTICE([$note=Credentials_Found,
                    $msg=fmt("Possible exposed credentials found - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
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

event HTTPAppExposure::stream_cred_data(f: fa_file, data: string) {
    local c: connection;
    for ( id in f$conns ) {
        # Loop until we collect the ID of the connection
        c = f$conns[id];
        break;
    }

    if ( c$start_time > network_time()-10secs ) {
        check_cred_sigs(c, f, data);
    }
}


event file_sniff(f: fa_file, meta: fa_metadata) {
    if(! meta?$mime_type) return;
    if(! f?$conns) return;

    if(!(meta$mime_type in HTTPAppExposure::cred_observed_mime_types)) return;

    Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=HTTPAppExposure::stream_cred_data]);

}

