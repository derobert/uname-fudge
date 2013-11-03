#include "ArchOps.h"

void SysCallInfo::pull_syscall() {
	syscall_num = arch_get_syscall();
	syscall_num_valid = true;
}

void SysCallInfo::pull_registers() {
	// if we ever port to SPARC, then data and addr are backwards
	// according to the manpage.
	if (-1 == ptrace(PTRACE_GETREGS, pid, nullptr, &registers))
		throw std::error_code(errno, std::generic_category());

	registers_valid = true;
}
