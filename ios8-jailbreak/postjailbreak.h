// jailbreak.h from openpwnage

#ifndef jailbreak_h
#define jailbreak_h

#include <mach/mach.h>

bool isA5orA5X(void);
void postjailbreak_remount(void);
void postjailbreak_bootstrap(void);
bool postjailbreak_check_status(void);
bool postjailbreak_check_sbshowapp(void);
void postjailbreak_add_sbshowapp(void);
void postjailbreak_uicache(void);
void postjailbreak_untether(void);
void postjailbreak_openssh(void);
void postjailbreak_tweaks(void);
void postjailbreak_respring(void);

extern char *ckernv;
extern bool install_openssh;
extern bool reinstall_strap;
extern bool untether_on;
extern bool tweaks_on;

#endif /* jailbreak_h */
