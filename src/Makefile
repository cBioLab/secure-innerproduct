TOPDIR:=$(realpath $(dir $(lastword $(MAKEFILE_LIST))))/
CFLAGS=-O3
CFLAGS+= -I$(TOPDIR)include -I$(TOPDIR)../../cybozulib/include/ -I$(TOPDIR)../../mie/include -I$(TOPDIR)../../xbyak/ -I$(TOPDIR)../../Lifted-ElGamal/include/ -I$(TOPDIR)../include/
LDFLAGS+= -lgmp -lgmpxx -lcrypto
SERVER_OBJS=comm.o inner_server.o
CLIENT_OBJS=comm.o inner_client.o

all: server client

clean:
	rm ../bin/server ../bin/client $(SERVER_OBJS) $(CLIENT_OBJS) *~

.SUFFIXES: .cpp

.cpp.o:
	$(CXX) -c $< -o $@ $(CFLAGS) -fopenmp

server: $(SERVER_OBJS)
	$(CXX) $(SERVER_OBJS) -o $@ $(LDFLAGS) -fopenmp
	mv server $(TOPDIR)../bin/

client: $(CLIENT_OBJS)
	$(CXX) $(CLIENT_OBJS) -o $@ $(LDFLAGS) -fopenmp
	mv client $(TOPDIR)../bin/

