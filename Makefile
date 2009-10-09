LUAPATH=/usr/local/share/lua/5.1
CPATH=/usr/local/lib/lua/5.1

TARGET=cyrussasl.so
OBJS=cyrussasl.o

# Linux
#CFLAGS=-g -O2 -fpic -I/usr/include/lua5.1
#LDFLAGS=-O -shared -fpic -lsasl2

# MacOS
CFLAGS=-g -Wall -O2
LDFLAGS=-bundle -undefined dynamic_lookup -lsasl2
MACOSX_VERSION=10.5

all: $(TARGET)

install: $(TARGET)
	cp $(TARGET) $(CPATH)

clean:
	rm -f *.o *.so

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $(TARGET) 

.c.o:
	$(CC) $(CFLAGS) -fno-common -c $< -o $@
