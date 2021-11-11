##! Zeek scripts that are used to detect suspicious data in detected HTTP payloads

# Extend the existing HTTPAppExposure module
module HTTPAppExposure;

export {

        const php_code_sigs = 
                /(\$_\.*echo)/i |
                /(\$_get\.*echo)/i |
                /(\$_post\.*echo)/i |
                /(\$_request\.*echo)/i |
                /(\$sql)/i |
                /(mysqli\()/i |
                /(pdo\()/i |
                /(file_include\()/i |
                /(file_get_contents\()/i |
                /(include\()/i |
                /(shell_exec\()/i |
                /(system\()/i |
                /(exec\()/i &redef;

        const phpinfo_sigs = /phpinfo\(\)/i &redef;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
        if(Site::is_local_addr(c$id$resp_h) &&
           c$http?$status_code &&
           c$http$status_code in HTTPAppExposure::app_success_status_codes &&
           php_code_sigs in data) {
                # Check for field existence and assign defaults
                local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
                local method = c$http?$method ? c$http$method : "<unknown>";
                local uri = c$http?$uri ? c$http$uri : "<unknown>";
                local respPort = port_to_count(c$id$resp_p);

                NOTICE([$note=Suspect_PHP_Code,
                        $msg=fmt("HTTP payload of website contains suspicious PHP code exposure - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                        $sub=fmt("%s", data),
                        $conn=c,
                        $identifier=cat(c$id$resp_h, uri),
                        $suppress_for=1day]);

        }
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
        # print fmt("OBJECT: %s", c);
        if(Site::is_local_addr(c$id$resp_h) &&
           c$http?$status_code &&
           c$http$status_code in HTTPAppExposure::app_success_status_codes &&
           phpinfo_sigs in data) {
                # Check for field existence and assign defaults
                local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
                local method = c$http?$method ? c$http$method : "<unknown>";
                local uri = c$http?$uri ? c$http$uri : "<unknown>";
                local respPort = port_to_count(c$id$resp_p);

                NOTICE([$note=PhpInfo,
                        $msg=fmt("Local site found exposing a phpinfo page - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                        $sub=fmt("%s", data),
                        $conn=c,
                        $identifier=cat(c$id$resp_h, uri),
                        $suppress_for=1day]);

        }
}
