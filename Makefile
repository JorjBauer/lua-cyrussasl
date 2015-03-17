# Linux (tested w/ Debian Lenny, probably works on many others as well)
#CFLAGS=-g -O2 -fpic -I/usr/include/lua5.1
#LDFLAGS=-O -shared -fpic -lsasl2
#LUAPATH=/usr/share/lua/5.1
#CPATH=/usr/lib/lua/5.1

# OpenBSD 4.8 (thanks lintech@yandex.ru)
#CFLAGS=-g -O2 -fpic -I/usr/include
#LDFLAGS=-O -shared -fpic -lsasl2
#LUAPATH=/usr/share/lua/5.1
#CPATH=/usr/lib/lua/5.1

#FreeBSD 10.1 (thanks peter@flytrace.com)
#CFLAGS=-g -O2 -fpic -I/usr/local/include/lua51 -I/usr/local/include
#LDFLAGS=-v -O -shared -fpic -lsasl2 -L/usr/local/lib
#LUAPATH=/usr/local/share/lua/5.1
#CPATH=/usr/local/lib/lua/5.1

# MacOS (tested with 10.6, 10.7, 10.8)
CFLAGS=-g -Wall -O2
LDFLAGS=-bundle -undefined dynamic_lookup -lsasl2
MACOSX_VERSION=10.5
LUAPATH=/usr/local/share/lua/5.1
CPATH=/usr/local/lib/lua/5.1

#########################################################
#
# YOU SHOULD NOT HAVE TO CHANGE ANYTHING BELOW THIS LINE.
# If you do, then send me email letting me know what and 
# why!
# -- Jorj Bauer <jorj@jorj.org>
#
#########################################################

BRANCH_VERSION=.branch_version
BUILD_VERSION=.build_version
TARGET=cyrussasl.so
OBJS=cyrussasl.o luaabstract.o context.o

all: $(TARGET)

install: $(TARGET)
	cp $(TARGET) $(CPATH)

clean:
	rm -f *.o *.so *~

distclean: clean
	rm -f $(BUILD_VERSION) $(BRANCH_VERSION)

$(TARGET): version $(OBJS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -DVERSION="\"$$(cat VERSION).$$(cat $(BRANCH_VERSION))-$$(cat $(BUILD_VERSION))\"" -fno-common -c $< -o $@

# Dependencies
cyrussasl.c: context.h luaabstract.c luaabstract.h

luaabstract.c: luaabstract.h

context.c: context.h

# build_version stuff
.PHONY: version branch_version

version:
	@if ! test -f $(BUILD_VERSION); then echo 0 > $(BUILD_VERSION); fi
	@echo $$(($$(cat $(BUILD_VERSION)) + 1)) > $(BUILD_VERSION)
	@if ! test -f $(BRANCH_VERSION); then git log --pretty=oneline -1|cut -c1-8 > $(BRANCH_VERSION); fi

