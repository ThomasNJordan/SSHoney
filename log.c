/*********************************************************************/
/* log.c: A logging function for the SSHoney program                 */
/* Name: Thomas Jordan                                               */
/* Last Modified: 5/24/2023                                          */
/*********************************************************************/

#include <time.h>

void logToFile(const char* input, char logName[], int mode) {
    FILE* file = fopen(logName, "a");  /* Appends information to file */

    /* Get the current time */
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    assert(tm); /* Did this variable get created correctly */

    if (mode == 0) { /* Init mode */
        fprintf(file, "Server started | Timestamp: %s\n", asctime(tm));
    } /* fi */
    else if (mode == 1) { /* Logging mode */
        if (file != NULL) {
            fprintf(file, "Input: %s | Timestamp: %s\n", input, asctime(tm));
            fclose(file);  /* Exit from file */
        } /* fi */
        else { /* Sanity check that file write succeeded */
            FatalError("Error reading to log file.");
        } /* esle */
    } /* fi */
    else { /* Check that mode was valid */
        FatalError("Enter a valid input mode");
    } /* esle */
}


