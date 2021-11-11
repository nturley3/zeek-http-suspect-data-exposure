##! Bro scripts that are used to detect suspicious data in detected HTTP payloads

# Extend the existing HTTPAppExposure module
module HTTPAppExposure;

export {

        const app_index_sig = /index[[:space:]]of[[:space:]]\/.*/i |
                              /\[to[[:space:]]parent[[:space:]]directory\]/i &redef;

        # Check for default pages on Ubuntu (Apache), Red Hat (Apache), Windows IIS and Nginx
        const app_default_page_sig = 
                                /apache[[:digit:]]?[[:space:]]ubuntu[[:space:]]default[[:space:]]page/i |
                                /(red[[:space:]]hat[[:space:]]enterprise[[:space:]]linux[[:space:]]test[[:space:]]page)/i |
                                /(welcome[[:space:]]to[[:space:]]nginx!)/i |
                                /iis[[:space:]]windows[[:space:]]server/i &redef;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
        if(Site::is_local_addr(c$id$resp_h) &&
           c$http?$status_code &&
           c$http$status_code in HTTPAppExposure::app_success_status_codes &&
           app_index_sig in data) {
                # Check for field existence and assign defaults
                local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
                local method = c$http?$method ? c$http$method : "<unknown>";
                local uri = c$http?$uri ? c$http$uri : "<unknown>";
                local respPort = port_to_count(c$id$resp_p);

                NOTICE([$note=App_Index_Found,
                        $msg=fmt("HTTP payload of website contains site index exposure - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                        $sub=fmt("%s", data),
                        $conn=c,
                        $identifier=cat(c$id$resp_h, uri),
                        $suppress_for=1day]);

        }
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
        if(Site::is_local_addr(c$id$resp_h) &&
           c$http?$status_code &&
           c$http$status_code in HTTPAppExposure::app_success_status_codes &&
           app_default_page_sig in data) {
                # Check for field existence and assign defaults
                local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
                local method = c$http?$method ? c$http$method : "<unknown>";
                local uri = c$http?$uri ? c$http$uri : "<unknown>";
                local respPort = port_to_count(c$id$resp_p);

                NOTICE([$note=Default_Install_Page_Found,
                        $msg=fmt("Default web server install page found - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                        $sub=fmt("%s", data),
                        $conn=c,
                        $identifier=cat(c$id$resp_h, uri),
                        $suppress_for=1day]);

        }
}
