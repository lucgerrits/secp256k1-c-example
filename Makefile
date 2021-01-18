
CXX = g++-8

libs = -lsecp256k1
libs += #-lprofiler

includes = -I secp256k1/includes
includes += -I secp256k1/src/

#######objects for main prog:
app_objects = app.cpp
app_static_lib = cryptopp/libcryptopp.a
app_static_lib += secp256k1/.libs/libsecp256k1.a

#some flags
flag_global = -O2 -std=c++11  -pg  #eosio is on standart c++17  -pg 
flag_main = -Wall 

all: app

app: $(app_objects)
	$(CXX) $(flag_global) $(flag_main) -DNDEBUG $(app_objects) $(libs) $(includes) -o app $(app_static_lib) 

# utils.o: utils.hpp
# 	$(CXX) $(flag_global) $(libs) $(includes) -c utils.hpp  -o utils.o 


clean: 
	rm -fr app
	rm -fr *.o *.out.* *.out *.stats *.a