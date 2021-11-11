##! Detect access to potentially suspicious scripts.
##! Goal is to check extracted files against YARA signatures (e.g. webshells)

@load base/utils/site
@load base/utils/urls
@load base/frameworks/notice
@load base/protocols/http/entities

module FileSniff;

export {

    redef enum Notice::Type += {
        ## Indicates that a PHP script was downloaded
        x_php,
        ## Indicates that a Shells script was downloaded
        x_shellscript,
        ## Indicates that a Perl script was downloaded
        x_perl,
        ## Indicates that a Python script was downloaded
        x_python
    };

    ## Defines the HTTP status codes we are interested in when detecting
    ## suspicious file access
    global http_success_status_codes: set[count] = {
        200,
        201,
        202,
        203,
        204,
        205,
        206,
        207,
        208,
        226,
        304
    };

    ## Regular expression to match direct sensitive files
    global mime_to_ext: table[string] of string = {
            ["text/x-php"] = "php",
            ["text/x-shellscript"] = "sh",
            ["text/x-perl"] = "pl",
            ["text/x-python"] = "py",
            ["text/plain"] = "txt",
            ["text/json"] = "json"
    };

    ## Path to save extracted files to
    const path = "/bd/logs/extract_files/" &redef;

    ## This table contains a conversion of common mime types to their
    ## corresponding 'normal' file extensions.
    ## Table is left here for reference
    #const common_types: table[string] of string = {
        #["text/plain"] = "txt",
        #["text/html"] = "html",
        #["text/json"] = "json",
        #["text/x-perl"] = "pl",
        #["text/x-python"] = "py",
        #["text/x-ruby"] = "rb",
        #["text/x-lua"] = "lua",
        #["text/x-php"] = "php",
        #["image/gif"] = "gif",
        #["image/x-ms-bmp"] = "bmp",
        #["image/jpeg"] = "jpg",
        #["image/png"] = "png",
        #["application/x-dosexec"] = "exe",
        #["application/msword"] = "doc",
        #["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
        #["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
        #["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = "pptx",
        #["application/xml"] = "xml",
        #["application/java-archive"] = "jar",
        #["application/x-java-applet"] = "jar",
        #["application/x-shockwave-flash"] = "swf",
        #["application/javascript"] = "js"
    #};
}

# Generates notice event for payload and extracted files
function gen_notice(c: connection, f:fa_file, note: Notice::Type, msg: string, extract_file: string)
{
       NOTICE([$note=note,
               $msg=fmt("%s", msg),
               $sub=fmt("%s%s (%s %s) - File Extract: %s, Payload: %s", f$http$host, f$http$uri, f$http$status_code, f$http$status_msg, extract_file, f$bof_buffer),
               $conn=c,
               $identifier=cat(f$http$id$resp_h, f$http$id$resp_p, f$http$uri),
               $suppress_for=1day]);
}

event file_new(f: fa_file)
{
    print fmt("NEW FILE: %s\n\n", f);
}

# Sniffs script files, generates notices and extract flagged files
event file_sniff(f: fa_file, meta: fa_metadata)
{
    # Return if none of the relevant fields are defined
    if ( !meta?$mime_type ) return;
    if ( ! f?$conns ) return;

    local c: connection;

    if ( f?$http && meta$mime_type in FileSniff::mime_to_ext && Site::is_local_addr(f$http$id$orig_h) && f$http$status_code in FileSniff::http_success_status_codes)
    {
        # Set the extraction filename and determine an "appropriate" file extension
        local ftype = "";
        if ( meta$mime_type in mime_to_ext ) {
            ftype = mime_to_ext[meta$mime_type];
        } else {
            ftype = split_string(meta$mime_type, /\//)[1];
        }

        local fname = fmt("%s%s-%s.%s", path, f$source, f$id, ftype);
        print fmt("Extracting file: %s", fname);

        # The "conns" field of fa_file should hold all the connection records over which the file was transferred, if any
        # Iterare over the conns records and generate appropriate notices
        for (cid in f$conns)
        {
            c = f$conns[cid];
            # print "file_mime_type", meta$mime_type;

            switch (meta$mime_type) {
                case "text/x-shellscript":
                    gen_notice(c, f, x_shellscript, "Detected x-shellscript mimetype file access from campus system", fname);
                    break;
                case "text/x-php":
                    gen_notice(c, f, x_php, "Detected x-php script mimetype file access from campus system", fname);
                    break;
                case "text/x-python":
                    gen_notice(c, f, x_python, "Detected x-python script mimetype file access from campus system", fname);
                    break;
                case "text/x-perl":
                    gen_notice(c, f, x_perl, "Detected x-perl script mimetype file access from campus system", fname);
                    break;
                case "text/plain":
                    gen_notice(c, f, x_perl, "Detected text-plain script mimetype file access from campus system", fname);
                    break;
                case "text/json":
                    gen_notice(c, f, x_perl, "Detected text-json script mimetype file access from campus system", fname);
                    break;
                default:
                    return;
            }
            
        }

        # Invoke file extraction analyzer
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }
}

