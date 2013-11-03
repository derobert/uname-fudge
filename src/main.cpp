#include <algorithm>
#include <boost/program_options.hpp>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <signal.h>
#include <cerrno>
#include <sys/syscall.h>

#include "ArchOps.h"
#include "LogStream.h"
#include "UnameFudger.h"

namespace po = boost::program_options;

typedef std::vector<std::string> string_vec;

void parse_command_line(int argc, char *argv[], po::variables_map &vm);
pid_t start_child(LogStream &, const string_vec &cmd);
void stop_child_signaling(LogStream &);

enum class ChildState {
	before_sigstop,
	outside_syscall,
	inside_syscall,
};
typedef std::unordered_map<pid_t, ChildState> ChildrenMap;

void waitpid_loop(LogStream &log, ChildrenMap &, UnameFudger &);

int main(int argc, char *argv[]) {
	po::variables_map vm;

	parse_command_line(argc, argv, vm);

	LogStream log;
	if (vm.count("log")) {
		// if not logging, leave ofstream closed, we'll just ignore the
		// errors. Idea from http://stackoverflow.com/a/8244052/27727
		// The boost answer also on that question doesn't seem to work.
		log.open(vm["log"].as<std::string>());
		if (!log) {
			std::cerr << "Could not open log: " << std::strerror(errno) 
			          << std::endl;
			return EXIT_FAILURE;
		}
	}

	UnameFudger fudge;
	fudge.set_release("3.11.0");

	stop_child_signaling(log);

	auto child = start_child(log, vm["cmd"].as<string_vec>());
	log(child) << "Initial child process started.\n";

	ChildrenMap children;
	children[child] = ChildState::before_sigstop;

	waitpid_loop(log, children, fudge);

}

std::unique_ptr<const char *[]>vector_to_argv(const string_vec &cmd) {
	std::unique_ptr<const char *[]> argv(new const char*[1+cmd.size()]);
	size_t i = 0;
	for (auto beg = cmd.cbegin(), end = cmd.cend(); beg < end; ++beg, ++i) {
		argv[i] = beg->c_str();
	}
	argv[i] = nullptr;
	
	return argv;
}

pid_t start_child(LogStream &log, const string_vec &cmd) {
	pid_t child = fork();

	if (child == -1) {
		std::cerr << "Fork failed: " << std::strerror(errno) << std::endl;
		exit(EXIT_FAILURE);
	} else if (child == 0) {
		// child
		auto argv = vector_to_argv(cmd);
		ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
		raise(SIGSTOP);
		execvp(cmd[0].c_str(), const_cast<char *const *>(argv.get()));
		std::cerr << "exec failed: " << std::strerror(errno) << std::endl;
		exit(EXIT_FAILURE);
	} else {
		// nothing special if parent
	}
	
	return child;
}

void stop_child_signaling(LogStream &log) {
	struct sigaction sa;
	if (-1 == sigaction(SIGCHLD, nullptr, &sa)) {
		log() << "Get sigaction for SIGCHLD: " << strerror(errno) << ".\n";
		log() << "This is non-fatal, but may slow things down.\n";
		return;
	}
	sa.sa_flags |= SA_NOCLDSTOP;
	if (-1 == sigaction(SIGCHLD, &sa, nullptr)) {
		log() << "Set SA_NOCLDSTOP: " << strerror(errno) << ".\n";
		log() << "This is non-fatal, but may slow things down.\n";
	}
}

void waitpid_loop(LogStream &log, ChildrenMap &children, UnameFudger &fudger)
{
	SysCallInfo sc_info;

	while (1) {
		int status;
		log.flush();
		pid_t pid = waitpid(-1, &status, __WALL);
		if (-1 == pid) {
			switch (errno) {
				case ECHILD:
					log() << "No remaining children. We're done.\n";
					return;
				case EINTR:
					continue;
				default:
					log() << "waitpid: " << strerror(errno) << std::endl;
					continue;
			}
		} else if (0 == pid) {
			log() << "odd; waitpid returned 0 without WNOHANG. Ignoring.\n";
			continue;
		}

		if (WIFEXITED(status)) {
			log(pid) << "exited.\n";
			children.erase(pid);
			continue;
		} else if (!WIFSTOPPED(status)) {
			log(pid) << "got something besides stop or exit... status=" << status << ". Ignoring and hoping for the best.\n";
			continue;
		}

		auto state = children.find(pid);
		if (state == children.end()) {
			log(pid) << "WARNING: unexpected pid! Assuming outside syscall.\n";
			state = children.insert(std::make_pair(pid, ChildState::outside_syscall)).first;
		}
		
		if (ChildState::before_sigstop == state->second && SIGSTOP == WSTOPSIG(status)) {
			// this is the sigstop our child raises for us. Set up out
			// ptrace options, and suppress the signal.
			log(pid) << "Initial SIGSTOP. Setting up ptrace.\n";
			if (-1 == ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEFORK|PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEVFORK)) {
				log(pid) << "Failed to set ptrace options: " << strerror(errno) << ".\nMurdering child and aborting.\n";
				kill(pid, SIGKILL);
				return;
			}
			state->second = ChildState::outside_syscall;
			goto resume_child;
		} else if ((SIGTRAP|0x80) == WSTOPSIG(status)) {
			switch (state->second) {
				case ChildState::outside_syscall:
					state->second = ChildState::inside_syscall;
					break;
				case ChildState::inside_syscall:
					state->second = ChildState::outside_syscall;
					sc_info.set_pid(pid);
					if (SYS_uname == sc_info.get_syscall()) {
						log(pid) << "Called uname: fudging result.\n";
						fudger.fudge(sc_info);
					}
					sc_info.release_pid();
					break;
				default:
					log(pid) << "Neither inside nor outside syscall. Uh-oh\n";
					break;
			}
			goto resume_child;
		} else if (0 != WSTOPSIG(status) && SIGTRAP != WSTOPSIG(status)) {
			// FIXME: need to handle group stop
			log(pid) << "Got signal " << WSTOPSIG(status) << std::endl;
			ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status));
			goto already_resumed;
		} else if (SIGTRAP == WSTOPSIG(status) && SIGTRAP != (status >> 8)) {
			switch (status >> 8) {
				case SIGTRAP|PTRACE_EVENT_VFORK<<8:
					log(pid) << "vfork\n";
					goto resume_child;
				case SIGTRAP|PTRACE_EVENT_FORK<<8:
					log(pid) << "fork\n";
					goto resume_child;
				case SIGTRAP|PTRACE_EVENT_CLONE<<8:
					log(pid) << "clone\n";
					goto resume_child;
				case SIGTRAP|PTRACE_EVENT_VFORK_DONE<<8:
					log(pid) << "vfork done\n";
					goto resume_child;
				case SIGTRAP|PTRACE_EVENT_EXEC<<8:
					log(pid) << "exec\n";
					goto resume_child;
				case SIGTRAP|PTRACE_EVENT_EXIT<<8:
					log(pid) << "exit\n";
					goto resume_child;
#if 0
/*
 * This one is Linux 3.4+ only, and only if we're using PTRACE_SEIZE,
 * which we're not.
 *
 * It also needs <linux/ptrace.h> which conflicts with the glibc
 * <sys/ptrace.h>...
*/
				case SIGTRAP|PTRACE_EVENT_STOP<<8:
					log(pid) << "stop\n";
					break;
#endif
				default:
					log(pid) << "umm, what? status = " << status << ". Ignoring.\n";
					goto resume_child;
			}
		} else if (SIGTRAP == WSTOPSIG(status)) {
			log(pid) << "Unexpected sigtrap... Ignoring and hoping!\n";
			goto resume_child;
		}

		log(pid) << "BUG: Should never get here... Restarting child and hoping for the best. Status = " << status << "\n";

resume_child:
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
already_resumed:
		(void)0; // no-op
	}
}

void parse_command_line(int argc, char *argv[], po::variables_map &vm) {
#define PVSS po::value<std::string>() /* lazy, unsure if each needs its own */
	po::options_description opts_general("General Options");
	opts_general.add_options()
		("help,h", "Display this help message")
		("log,l", PVSS, "Log our activities to a file (mainly for debugging)");
	po::options_description opts_override("Override Options");
	opts_override.add_options()
		("kernel-name,s", PVSS, "System name (\"Linux\")")
		("nodename,n", PVSS, "Node name (often hostname)")
		("kernel-release,r", PVSS, "Release (\"3.10-2-amd64\")")
		("kernel-version,v", PVSS, "Kernel version (often distro version)")
		("machine,m", PVSS, "Machine (\"x86_64\")");
#undef PVSS

	po::options_description opts_hidden("Hidden");
	opts_hidden.add_options()
		("cmd", po::value<string_vec>()->required(), "command");

	po::positional_options_description opts_positional;
	opts_positional.add("cmd", -1);

	po::options_description opts_all("Options");
	opts_all.add(opts_override)
	        .add(opts_general)
		    .add(opts_hidden);

	po::options_description opts_visible("");
	opts_visible.add(opts_override)
	            .add(opts_general);

	try {
		po::store(po::command_line_parser(argc, argv)
										 .options(opts_all)
										 .positional(opts_positional)
										 .run(),
				  vm);

		if (vm.count("help")) {
			std::cout << "uname-fudge OPTIONS [--] program [program-options]\n"
					  << opts_visible
					  << '\n';
			std::exit(EXIT_SUCCESS);
		}
		if (!vm.count("cmd")) {
			std::cerr << "USAGE:\n"
					  << "  uname-fudge OPTIONS [--] program [program-options]\n"
					  << "\n"
					  << "You didn't provide a program to run; perhaps you want\n"
					  << "to try --help.\n";
			std::exit(EXIT_FAILURE);
		}
	} catch (po::error &err) {
		std::cerr << "Error: " << err.what() << "\n"
		          << "\n"
		          << "You may want --help.\n";
		std::exit(EXIT_FAILURE);
	}
}
