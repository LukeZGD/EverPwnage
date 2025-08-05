// jailbreak.h from openpwnage

#ifndef jailbreak_h
#define jailbreak_h

#include <mach/mach.h>

void postjailbreak(bool untether_on);
bool isA5orA5X(void);

extern char *ckernv;
extern bool install_openssh;
extern bool reinstall_strap;

#endif /* jailbreak_h */
