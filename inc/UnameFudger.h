#ifndef UNAMEFUDGER_H
#define UNAMEFUDGER_H

#include <memory>
#include <string>
#include <sys/utsname.h>

#include "ArchOps.h"

class UnameFudger {
	public:
#		define MAKE_SETTER(m) inline void set_##m(std::string s) {   \
			if (s.length() >= sizeof((struct utsname){0}.m))          \
				throw std::range_error("String too long for "#m);     \
				m.reset(new std::string(s));                          \
		}
		MAKE_SETTER(sysname)
		MAKE_SETTER(nodename)
		MAKE_SETTER(release)
		MAKE_SETTER(version)
		MAKE_SETTER(machine)
		MAKE_SETTER(domainname)
#		undef MAKE_SETTER
	public:
		void fudge(SysCallInfo &);

	private:
		typedef std::unique_ptr<std::string> s_ptr;
		s_ptr sysname;
		s_ptr nodename;
		s_ptr release;
		s_ptr version;
		s_ptr machine;
		s_ptr domainname;
};

#endif
