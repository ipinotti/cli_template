#include <libconfig/cgi-lib.h>
#include <libconfig/html-lib.h>

/* need to declare a pointer variable of type LIST to keep track of our list */
extern LIST *head;
void cmdline2url(char *cmdline, char *url);
int url2cmdline(char *cmdline, char *url);
void cgi_main(char *progname);


