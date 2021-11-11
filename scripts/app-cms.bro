##! Bro scripts that are used to detect suspicious data in detected HTTP payloads

# Extend the existing HTTPAppExposure module
module HTTPAppExposure;

export {
        const drupal_install_sig = /form[[:space:]]class=\"install-select-language-form\"[[:space:]]data-drupal-selector=\"install-select-language-form\"[[:space:]]action=\"\/core\/install\.php\"/i |
                                   /choose[[:space:]]language[[:space:]][[:punct:]][[:space:]]drupal/i &redef;

        const wordpress_install_sig = /wordpress[[:space:]]\&rsaquo;[[:space:]]setup[[:space:]]configuration[[:space:]]file/i &redef;

        const joomla_install_sig = /joomla[[:punct:]][[:space:]]web[[:space:]]installer/i &redef;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
        # This is a processing efficiency tactic here. Return early from the event.
        if((!Site::is_local_addr(c$id$resp_h)) || (!c$http?$status_code) || !(c$http$status_code in HTTPAppExposure::app_success_status_codes)) {
            return;
        }

        # Check for field existence and assign defaults
        local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
        local method = c$http?$method ? c$http$method : "<unknown>";
        local uri = c$http?$uri ? c$http$uri : "<unknown>";
        local respPort = port_to_count(c$id$resp_p);

        if(drupal_install_sig in data) {
            NOTICE([$note=Drupal_Install_Found,
                    $msg=fmt("Drupal installation site found - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                    $sub=fmt("%s", data),
                    $conn=c,
                    $identifier=cat(c$id$resp_h, uri),
                    $suppress_for=1day]);

        } else if(wordpress_install_sig in data) {
            NOTICE([$note=Wordpress_Install_Found,
                    $msg=fmt("Wordpress installation site found - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                    $sub=fmt("%s", data),
                    $conn=c,
                    $identifier=cat(c$id$resp_h, uri),
                    $suppress_for=1day]);

        } else if(joomla_install_sig in data) {
            NOTICE([$note=Joomla_Install_Found,
                    $msg=fmt("Joomla installation site found - Response: %s %s - URL: %s:%s%s", c$http$status_code, method, respHost, respPort, uri),
                    $sub=fmt("%s", data),
                    $conn=c,
                    $identifier=cat(c$id$resp_h, uri),
                    $suppress_for=1day]);

        } else {
            return;
        }
}
