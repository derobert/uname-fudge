#ifndef ARCHOPS_H
#define ARCHOPS_H

#include <sys/ptrace.h>
#include <sys/user.h>
#include <cassert>
#include <cstddef>
#include <cerrno>
#include <system_error>
#include <stdexcept>
#include <type_traits>
#include <bitset>

class SysCallInfo {
	public:
		SysCallInfo() = default;
		~SysCallInfo() = default;

	public:
		inline void set_pid(pid_t child) {
			assert(0 == pid);
			pid = child;
		}
		inline pid_t get_pid() {
			assert(0 != pid);
			return pid;
		}
		inline void release_pid() {
			assert(0 != pid);
			syscall_num_valid = false;
			registers_valid = false;
			pid = 0;
		}

	private:
		inline int arch_get_syscall();
		inline long arch_get_arg(int);
		void pull_syscall();
		void pull_registers();

	public:
		inline int get_syscall() {
			assert(0 != pid);

			if (!syscall_num_valid)
				pull_syscall();
			
			return syscall_num;
		}
		inline long get_arg(int x) {
			assert(0 != pid);
			assert(x >= 1 && x <= 6);

			if (!registers_valid)
				pull_registers();

			return arch_get_arg(x);
		}


	private:
		pid_t pid = 0;
		
		int syscall_num = 0;
		bool syscall_num_valid = false;
		struct user_regs_struct registers;
		bool registers_valid = false;

};

template<size_t L>class ChildPointer {
	public:
		ChildPointer(long child_addr) {
			child_offset = child_addr % sizeof(long);
			child_base = child_addr - child_offset;
		}
		~ChildPointer() {
			// TODO. Needs to write back all the dirty data.
		}

	public:
		void copy_to(size_t offset, const char *src, size_t len) {
			// TODO. This is the hard one.
		}

	public:
		ChildPointer(const ChildPointer &) = delete;
		ChildPointer &operator=(const ChildPointer &) = delete;
		ChildPointer(const ChildPointer &&) = delete;
		ChildPointer &operator=(const ChildPointer &&) = delete;

	private:
		long child_base;
		int child_offset;

	private:
		static constexpr auto max_words = L/sizeof(long) + 2;
		union {
			long words[max_words];
			char bytes[max_words * sizeof(long)];
		} data;
		std::bitset<max_words> valid, dirty;

};

#if __x86_64__
inline int SysCallInfo::arch_get_syscall() {
	constexpr auto regs_offset = offsetof(struct user, regs);
	constexpr auto rax_offset = offsetof(struct user_regs_struct, orig_rax);
	constexpr auto rax = regs_offset+rax_offset;
	
	errno = 0;
	auto res = ptrace(PTRACE_PEEKUSER, pid, rax, nullptr);
	if (errno)
		throw std::error_code(errno, std::generic_category());

	return res;
}

inline long SysCallInfo::arch_get_arg(int argnum) {
	switch (argnum) {
		case 1:
			return registers.rdi;
		case 2:
			return registers.rsi;
		case 3:
			return registers.rdx;
		case 4:
			return registers.r10;
		case 5:
			return registers.r8;
		case 6:
			return registers.r9;
		default:
			throw std::invalid_argument("Invalid argument number");
	}
}

#elif __i386__

#else
#error Uknown architecture; please add 
#endif

#endif
