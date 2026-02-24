CC_x64 = x86_64-w64-mingw32-gcc
CC_x86 = i686-w64-mingw32-gcc

CFLAGS = -w -Wno-incompatible-pointer-types -Os -DBOF -masm=intel

SRC = src/edr_enum_bof.c
BIN = _bin

all: x64 x86

x64: $(SRC)
	$(CC_x64) $(CFLAGS) -c $(SRC) -o $(BIN)/edr_enum_bof.x64.o -I src

x86: $(SRC)
	$(CC_x86) $(CFLAGS) -c $(SRC) -o $(BIN)/edr_enum_bof.x86.o -I src

clean:
	rm -f $(BIN)/*.o
