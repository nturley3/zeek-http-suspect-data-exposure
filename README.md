# Sensitive HTTP Data Exposure/Leak Detection

## Purpose
Detects the presence of potentially sensitive information in HTTP payloads
such as debug information, credentials, site indexes, installation files, and more.
This package is ideal for checking data hygiene and reducing the attack surface.

## Installation/Upgrade

This is easiest to install through the Zeek package manager:

	zkg refresh
	zkg install https://github.com/nturley3/zeek-http-suspect-data-exposure

If you need to upgrade the package:

	zkg refresh
	zkg upgrade https://github.com/nturley3/zeek-http-suspect-data-exposure 

See the [Zeek Package Manager Docs](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.

## Generated Outputs

This script generates multiple notices:

| Notice | msg field | sub field |  Description |
| ----- | ----- | ----- | ----- |
| HTTPAppExposure::App_Error_Found | HTTP payload of website contains application errors - Response: \<status code\> - URL: \<url\> | Excerpt of Data | Generated when various signatures of application errors have been detected. |
| HTTPAppExposure::Suspect_PHP_Code | HTTP payload of website contains suspicious PHP code exposure - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when an application is detected exposing PHP code. |
| HTTPAppExposure::PhpInfo | Local site found exposing a phpinfo page - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when the a debug phpinfo() page is detected. |
| HTTPAppExposure::App_Index_Found |HTTP payload of website contains site index exposure - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when an application directory index is exposed (e.g. Apache directory index). |
| HTTPAppExposure::Default_Install_Page_Found | Default web server install page found - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when a default Operating System or Web Server page is identified. | 
| HTTPAppExposure::Credentials_Found | Possible exposed credentials found - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when an attempt was made to identify exposed credentials in files or other objects exposed on a web service. |
| HTTPAppExposure::Drupal_Install_Found | Drupal installation site found- Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when a Drupal installation page was found. |
| HTTPAppExposure::Wordpress_Install_Found | Wordpress installation site found - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when a Wordpress installation page was found. |
| HTTPAppExposure::Joomla_Install_Found | Joomla installation site found - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when a Joomla installation page was found. |
| HTTPAppExposure::PhpMyAdmin_App_Found | PHPMyAdmin management application found - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when an exposed PHPMyAdmin application was detected. |
| HTTPAppExposure::Tomcat_Install_Found | Tomcat default installation site found - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when a Tomcat default installation page was found. |
| HTTPAppExposure::Tomcat_Manager_Found | Tomcat manager with basic authentication found - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | \<respHost\>:\<respPort\>\<uri\> (username: \<username\>, password: \<password\>) | Generated when a Tomcat application server management page was found and is using basic, unencrypted authentication. |
| HTTPAppExposure::Apache_Server_Status_Found | Possible Apache Server Status Page (Apache status module) found - Response: \<status code\> \<method\> - URL: \<respHost\>:\<respPort\>\<uri\> | Excerpt of Data | Generated when an Apache Server Status page was found. |

## Usage

A security analyst can examine the generated notice logs for potential organization vulnerabilities.
- Application errors or exposed PHP code could indicate a vulnerable, misbehaving, or broken application.
- Debug information, status pages, and index pages aids threat actors' reconnaissance and may expose credentials or links to sensitive files.
- Application install pages could be used to install malicious sites and compromise servers.
- Default web pages could indicate a misconfigured, unhardened, or abandoned (and potentially unpatched) server.
- Administration tools are of interest and commonly targeted by threat actors.


Type: Data Hygiene, Threat Hunting