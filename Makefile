CPPFLAGS := -iquote inc
CXXFLAGS := -O0 -g -Wall -Werror --std=gnu++11 
LDFLAGS  := -lboost_program_options

SOURCES := $(wildcard src/*.cpp)
OBJECTS := $(patsubst src/%.cpp,obj/%.o,$(SOURCES))
DEPS    := $(patsubst src/%.cpp,obj/%.dep,$(SOURCES))

all: uname-fudge

clean:
	rm -f uname-fudge $(OBJECTS) $(DEPS)

uname-fudge: $(OBJECTS)
	$(CXX) $(LDFLAGS) -o "$@" $^

obj/%.o: src/%.cpp
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) -o "$@" "$<"

obj/%.dep: src/%.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MM -MF "$@" -MT "obj/$*.o obj/$*.dep" "$<"

include $(DEPS)
