#include "mail.h"
#include <stdio.h>
#include <curl/curl.h>

int sendEmail(const char *access_token, const char *email_message) {
    CURL *curl;
    CURLcode res = CURLE_OK;

    // Initialize LibCurl
    curl = curl_easy_init();
    if (curl) {
        // Set the Gmail API endpoint URL
        const char *url = "https://www.googleapis.com/gmail/v1/users/me/messages/send";

        // Create the JSON payload for the email message
        char json_data[2048];
        snprintf(json_data, sizeof(json_data), "{\"raw\":\"%s\"}", email_message);

        // Set up the HTTP POST request
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);

        // Set up HTTP headers, including authorization with the access token
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Authorization: Bearer ");
        headers = curl_slist_append(headers, access_token);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Perform the HTTP request
        res = curl_easy_perform(curl);

        // Clean up
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    // Check for errors
    if (res != CURLE_OK) {
        fprintf(stderr, "Curl failed: %s\n", curl_easy_strerror(res));
        return 1; // Error
    }

    return 0; // Success
}