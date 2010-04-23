/**********************************************
* Policy Map header file
* Thomás Del Grande 
* 2008 - PD3 Tecnologia
***********************************************/

/* Policy Map */
void do_policy_description(const char *cmdline);
void do_policy_mark(const char *cmdline);
void config_policy_bw(const char *cmdline);
void config_policy_ceil(const char *cmdline);
void config_policy_queue(const char *cmdline);
void config_policy_realtime(const char *cmdline);
void do_policymap(const char *cmdline);
void quit_mark_config(const char *cmdline);
void policymap_done(const char *cmdline);

/* Service Policy*/
void no_service_policy(const char *cmdline);
void do_service_policy(const char *cmdline);
