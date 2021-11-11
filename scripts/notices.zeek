##! Zeek scripts that are used to detect suspicious data in detected HTTP payloads

@load base/frameworks/notice

module HTTPAppExposure;

export {
        redef enum Notice::Type += {
                ## Generated if suspicious HTTP payload data is detected
                App_Error_Found,
                ## Generated if suspicious HTTP payload data is detected
                Suspect_PHP_Code,
                ## Generated if PHPINFO() is found in page
                PhpInfo,
                ## Generated if site index page is found
                App_Index_Found,
                ## Generated if site default install page is found
                Default_Install_Page_Found,
                ## Generated if site is found with possible presence of user/system credentials
                Credentials_Found,
                ## Generated when Drupal installation site found
                Drupal_Install_Found,
                ## Generated when Wordpress installation site found
                Wordpress_Install_Found,
                ## Generated when Joomla installation site found
                Joomla_Install_Found,
                ## Generated when a PHPMyAdmin app console is found
                PhpMyAdmin_App_Found,
                ## Generated when a Tomcat install is found
                Tomcat_Install_Found,
                ## Generated when a Tomcat install is found
                Tomcat_Manager_Found,
                ## Generate when an Apache Server Status page is found
                Apache_Server_Status_Page_Found,
        };
}
