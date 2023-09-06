
OPENFHE_LOCATION=/usr/local
OPENFHE_STATIC_LIBS=$(OPENFHE_LOCATION)/lib/libOPENFHEpke_static.a $(OPENFHE_LOCATION)/lib/libOPENFHEcore_static.a
OPENFHE_INCLUDES=-I $(OPENFHE_LOCATION)/include/openfhe/core -I $(OPENFHE_LOCATION)/include/openfhe/pke -I $(OPENFHE_LOCATION)/include/openfhe/
OPENFHE_MISC=-DOPENFHE_VERSION=1.0.3 -Wno-parentheses -DMATHBACKEND=4
OPENFHE=$(OPENFHE_MISC) $(OPENFHE_STATIC_LIBS) $(OPENFHE_INCLUDES)

JSON_LIBS=-ljsoncpp

SOURCES=src
BINARIES=bin
TESTS=tests

CXX=g++
# -pedantic left out for use of uint128_t
#C++ filesystem flag may or may not be needed, depending on compiler
CPPFLAGS= -std=c++17 -lstdc++fs -pthread -Wall -Werror -fopenmp
#Need to account for newer systems
OS_VERS := $(shell lsb_release -a 2>/dev/null | grep Description | awk '{ print $$2 "-" $$3 }')
OS_NUM := $(word 3, OS_VERS)
ifneq ($(OS_NUM),18.04.6)
	CPPFLAGS += -Wno-error=deprecated-declarations
endif

all: drivers hashes

release: CPPFLAGS += -O3
release: drivers
	
debug: CPPFLAGS += -ggdb3
debug: drivers
	
drivers: receiver sender gen_params aggregate site_decrypt sender_encrypt

hashes: CPPFLAGS += -lssl -lcrypto
hashes: hash_single hash_many_to_bins

test: CPPFLAGS += -ggdb3
test: $(wildcard $(TESTS)/*.cpp)
	$(foreach f,$^,$(CXX) $f $(CPPFLAGS) $(OPENFHE)  -o $(basename $^);)

%: $(SOURCES)/%.cpp
	mkdir -p $(BINARIES)
	$(CXX) $<  $(CPPFLAGS) $(OPENFHE) -o $(BINARIES)/$@


#hash: src/hash_single.cpp src/hash_many_to_bins.cpp
#	mkdir -p $(BINARIES)
#	$(CXX) $< $(CPPFLAGS) -o $(BINARIES)/$@ -lssl -lcrypto


utilities/%: utilities/%.cpp
	mkdir -p $(BINARIES)
	$(CXX) $< $(CPPFLAGS) -o $(BINARIES)/$(notdir $@) $(JSON_LIBS)


clean:
	rm -f bin/*
	

.PHONY: all test clean release debug
