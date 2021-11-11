##! Bro scripts that are used to detect suspicious data in detected HTTP payloads

# Extend the existing HTTPAppExposure module
module HTTPAppExposure;

event http_header(c: connection, is_orig: bool, name: string, value: string) {
        # This is a processing efficiency tactic here. Return early from the event.
        if((!Site::is_local_addr(c$id$resp_h)) 
            || (!c$http?$status_code) 
            || !(c$http$status_code in HTTPAppExposure::app_success_status_codes)) {
            return;
        }

        # Check for field existence and assign defaults
        local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
        local method = c$http?$method ? c$http$method : "<unknown>";
        local uri = c$http?$uri ? c$http$uri : "<unknown>";
        local respPort = port_to_count(c$id$resp_p);

        # PHPMyAdmin appears to send gzip compressed payloads back to the user in which JS
        # libraries gunzip on the client, so payload detection not the best approach. We instead look
        # for the presence of cookies being set with the client using common PhpMyAdmin application variables
        # Sample: SET-COOKIE - phpMyAdmin=v2c0u5j145j6q86o5pfivn1o20; path=/phpmyadmin/; HttpOnly

        if (/SET-COOKIE/ in name && /phpMyAdmin=.*;[[:space:]]path=.*/i in value) {
            # We want to extract the path variable set in the cookie (see sample)
            local cookie_parts: string_vec = split_string(value, /;/);
            local path: string_vec = split_string(cookie_parts[1], /=/);
            #print fmt("%s", path[1]);

            #print fmt("%s - %s", name, value);
            NOTICE([$note=PhpMyAdmin_App_Found,
                    $msg=fmt("PHPMyAdmin management application found - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                    $sub=fmt("%s", path[1]),
                    $conn=c,
                    $identifier=cat(c$id$resp_h, path[1]),
                    $suppress_for=1day]);
        } else {
            return;
        }
}
