##! Bro scripts that are used to detect suspicious data in detected HTTP payloads

module HTTPAppExposure;

export {
        # We only want to trigger on successful HTTP status codes detected in responses
        # Make global to this module only, not the entire Bro namespace
        const app_success_status_codes: set[count] = {
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
                304,
                500
        } &redef;
}
