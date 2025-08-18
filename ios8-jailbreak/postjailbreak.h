// jailbreak.h from openpwnage

#ifndef jailbreak_h
#define jailbreak_h

#include <mach/mach.h>

bool isA5orA5X(void);
void postjailbreak(void);

extern char *ckernv;
extern bool install_openssh;
extern bool reinstall_strap;
extern bool untether_on;
extern bool tweaks_on;

#endif /* jailbreak_h */
