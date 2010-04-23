#include "commandtree.h"

int user_getc (FILE *stream);
char **cish_completion (char *, int, int);
char *cish_command_generator (const char *, int);
int cish_questionmark (int, int);
int cish_execute (const char *);
cish_command *expand_token (const char *, cish_command *, int);
void config_file (const char *F);
void init_logwatch (void);
void add_logwatch (const char *);
int cish_completion_http (char *cmdline, char *base_url);
void setup_loopback(void);
int ctrlz (int, int);
int hardkey(void);
int test_expert_passwd(char *);

extern cish_command *command_root;
extern const char *_cish_source;
extern char buf[1024];
extern int cish_timeout;
extern int cish_reload;

