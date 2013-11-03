#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <iostream>

#include "UnameFudger.h"

void UnameFudger::fudge(SysCallInfo &s) {
	assert(SYS_uname == s.get_syscall());

	ChildPointer<sizeof(struct utsname)> u_ptr(s.get_arg(1));
	
	if (release) {
		u_ptr.copy_to(offsetof(struct utsname, release), release->c_str(), release->length()+1);
	}
}
