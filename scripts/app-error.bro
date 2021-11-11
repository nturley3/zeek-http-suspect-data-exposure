##! Bro scripts that are used to detect suspicious data in detected HTTP payloads

# Extend the existing HTTPAppExposure module
module HTTPAppExposure;

export {
        # This is a good reference for app errors
        # https://github.com/danielmiessler/SecLists/blob/master/Pattern-Matching/errors.txt
        # List here is condensed to avoid false positives
        const app_error_sigs =
            /access[[:space:]]denied[[:space:]]for[[:space:]]user[[:space:]].*[[:space:]]\(using[[:space:]]password:[[:space:]]?(yes|no)\)/i |
            /can[[:punct:]]t[[:space:]]connect[[:space:]]to[[:space:]]local[[:space:]]mysql[[:space:]]server/i |
            /server[[:space:]]error[[:space:]]in/i |
            /error.*ORA-[[:digit:]]+/i |
            /you[[:space:]]have[[:space:]]an[[:space:]]error[[:space:]]in[[:space:]]your[[:space:]]sql[[:space:]]syntax/i |
            /error[[:space:]]occurred[[:space:]]while[[:space:]]processing[[:space:]]request/i &redef;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
        # This is a processing efficiency tactic here. Return early from the event.
        if((!Site::is_local_addr(c$id$resp_h)) || (!c$http?$status_code) || !(c$http$status_code in HTTPAppExposure::app_success_status_codes)) {
            return;
        }

        if(app_error_sigs in data) {
                # Check for field existence and assign defaults
                local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
                local method = c$http?$method ? c$http$method : "<unknown>";
                local uri = c$http?$uri ? c$http$uri : "<unknown>";
                local respPort = port_to_count(c$id$resp_p);

                NOTICE([$note=App_Error_Found,
                        $msg=fmt("HTTP payload of website contains application errors - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                        $sub=fmt("%s", data),
                        $conn=c,
                        $identifier=cat(c$id$resp_h, uri),
                        $suppress_for=1day]);

        }
}
