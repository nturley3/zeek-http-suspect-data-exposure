##! Zeek scripts that are used to detect suspicious data in detected HTTP payloads

# Extend the existing HTTPAppExposure module
module HTTPAppExposure;

export {
        const tomcat_sig: pattern = 
                        /It works !.*\n+.*setup Tomcat successfully/i &redef;

        ## The detected MIME types we want to observe 
        const tomcat_observed_mime_types: table[string] of string = {
            ["text/plain"] = "txt",
            ["text/html"] = "html",
        } &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    # Only process local responders
    if(!Site::is_local_addr(c$id$resp_h)) {
        return;
    }

    if(/WWW-AUTHENTICATE/i in name && /Tomcat Manager Application/i in value ) {
        # Check for field existence and assign defaults
        local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
        local method = c$http?$method ? c$http$method : "<unknown>";
        local uri = c$http?$uri ? c$http$uri : "<unknown>";
        local username = c$http?$username ? c$http$username : "<unknown>";
        local password = c$http?$password ? c$http$password : "<unknown>";
        local respPort = port_to_count(c$id$resp_p);

        NOTICE([$note=Tomcat_Manager_Found,
                $msg=fmt("Tomcat manager with basic authentication found - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                $sub=fmt("%s:%s%s (username: %s, password: %s)", respHost, respPort, uri, username, HTTP::default_capture_password == F ? "<blocked>" : password),
                $conn=c,
                $identifier=cat(c$id$resp_h, uri),
                $suppress_for=1day]);
    }
}

function check_tomcat_sigs(c: connection, f: fa_file, data: string): bool {
    local instances = find_all(data, tomcat_sig);

    for (inst in instances) {
        if(c?$http) {
            # Only process local responders and with an accepted status code
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

            NOTICE([$note=Tomcat_Install_Found,
                    $msg=fmt("Tomcat default installation site found - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
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

event HTTPAppExposure::stream_tomcat_data(f: fa_file, data: string) {
    local c: connection;
    for ( id in f$conns ) {
        # Loop until we collect the ID of the connection
        c = f$conns[id];
        break;
    }

    if ( c$start_time > network_time()-10secs ) {
        check_tomcat_sigs(c, f, data);
    }
}

event file_sniff(f: fa_file, meta: fa_metadata) {
    # Return if a MIME type has not been detected
    if(! meta?$mime_type) return;
    # Return if the file conns object has not been populated
    if(! f?$conns) return;

    # Return if we do not have a MIME type we care about
    if(!(meta$mime_type in HTTPAppExposure::tomcat_observed_mime_types)) return;

    Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=HTTPAppExposure::stream_tomcat_data]);

}