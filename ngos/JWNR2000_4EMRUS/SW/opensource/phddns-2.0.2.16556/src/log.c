/*
 * This file contains Netgear changes.
 * Changes are made to incorporate syslog messages.
 */
#include <stdarg.h>
#include <time.h>
#include <stdio.h>
#include <time.h>
#include <memory.h>
#include <string.h>

#include <sys/timeb.h>
/* Netgear start */
#include <syslog.h>
/* Netgear end */
#include "log.h"

#define BUFSIZE		4096

#ifdef _WIN32
#define snprintf	_snprintf
#endif

FILE *logFile = NULL;
int logLevel = 20;
/* Netgear start */
extern int oray_debuglevel;
/* Netgear end */

const char *logTime()
{
    static char buf[128];
	struct tm *tm1;
	time_t lTime;
	
	time(&lTime);
	tm1 = localtime(&lTime);
	strcpy(buf, asctime(tm1));
	char *p = strchr(buf, '\n');
	if (p) *p = '\0';
    return buf;
}

/* Netgear start */
void set_log_level(int argc, char *argv[]) {
     openlog(argv[0], LOG_PERROR | LOG_PID, LOG_DAEMON);

        if (argc >=4 && strcmp(argv[3], "-v") == 0)
        {
               oray_debuglevel = 1;
        }

        /* Logging Stuff */
        if (oray_debuglevel)
        {
                syslog(LOG_NOTICE, "oray Provisioning : Level Set To DEBUG");
                setlogmask(LOG_UPTO(LOG_DEBUG));
        }
        else
        {
                syslog(LOG_NOTICE, "oray Provisioning : Level Set To NOTICE");
                setlogmask(LOG_UPTO(LOG_NOTICE));
        }

}
/* Netgear end */

void log_open(const char *file, int level)
{
	logLevel = level;

	if (logFile)
		log_close();

	if (file && *file)
		logFile = fopen(file, "a+");
	if (!logFile) 
	{
		logFile = stderr;
		if (file && *file)
			LOG(1) ("Error open log file: %s\n", file);
	}
	//for test only!!!
	//logFile = stderr;
}

void log_close()
{
	if (logFile && logFile != stderr) {
		fclose(logFile);
		logFile = NULL;
	}
}

void log_print(const char *fmt, ...)
{
	char buf[BUFSIZE];
	
	va_list args;
	va_start(args, fmt);

	snprintf(buf, sizeof(buf), "%s| %s", logTime(), fmt);
	vfprintf(logFile, buf, args);

	fflush(logFile);

	va_end(args);
}
