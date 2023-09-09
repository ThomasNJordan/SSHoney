/* Header file for mail function */

#ifndef mail_h
#define mail_h

// Function to send an email using Gmail API
int sendEmail(const char *access_token, const char *email_message);

#endif