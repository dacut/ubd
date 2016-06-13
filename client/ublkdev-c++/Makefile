# Dependencies:
# AWS C++ SDK (must be manually compiled today).


TARGETS = libublkdev.so ublkdev-s3
CPPFLAGS = -I. -I../../src
CXXFLAGS = -std=c++11 -fPIC -Wall

LIB_SRCS = ublkdev.cc
LIB_OBJS = $(LIB_SRCS:%.cc=%.o)
LIB_LD = g++
LIB_LDFLAGS = -shared

S3_SRCS = s3.cc
S3_OBJS = $(S3_SRCS:%.cc=%.o)
S3_LD = g++
S3_LDFLAGS = -L.
S3_LIBS = -lublkdev -laws-cpp-sdk-s3 -laws-cpp-sdk-core

all: $(TARGETS)
libublkdev.so: $(LIB_OBJS)
	$(LIB_LD) $(LIB_LDFLAGS) -o $@ $(LIB_OBJS)

ublkdev-s3: $(S3_OBJS)
	$(S3_LD) $(S3_LDFLAGS) -o $@ $(S3_OBJS) $(S3_LIBS)

%.o: %.c
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $<

clean:
	rm -f $(TARGETS) *.o *~

.PHONY: all clean
