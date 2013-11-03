#ifndef LOGSTREAM_H
#define LOGSTREAM_H
#include <fstream>
#include <sys/types.h>
#include <string>

class LogStream {
	public:
		void open(const std::string &s) { return stream.open(s); }
		operator bool() { return stream; }
		std::ostream &flush() { return stream.flush(); }

	public:
		std::ostream &operator()() {
			return stream << "[GLOBAL]: ";
		}
		std::ostream &operator()(pid_t p) {
			return stream << "[" << p << "]: ";
		}
	
	private:
		std::ofstream stream;
};


#endif
