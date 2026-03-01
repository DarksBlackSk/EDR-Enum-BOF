CC_x64 = x86_64-w64-mingw32-gcc
CC_x86 = i686-w64-mingw32-gcc

CFLAGS = -w -Wno-incompatible-pointer-types -Os -DBOF -masm=intel
INCLUDE = -I src
BIN = _bin

all: local remote

# --- Local BOF ---
local: local_x64 local_x86

local_x64: src/edr_enum_bof.c
	$(CC_x64) $(CFLAGS) -c src/edr_enum_bof.c -o $(BIN)/edr_enum_bof.x64.o $(INCLUDE)

local_x86: src/edr_enum_bof.c
	$(CC_x86) $(CFLAGS) -c src/edr_enum_bof.c -o $(BIN)/edr_enum_bof.x86.o $(INCLUDE)

# --- Remote BOF ---
remote: remote_x64 remote_x86

remote_x64: src/edr_remote_bof.c
	$(CC_x64) $(CFLAGS) -c src/edr_remote_bof.c -o $(BIN)/edr_remote_bof.x64.o $(INCLUDE)

remote_x86: src/edr_remote_bof.c
	$(CC_x86) $(CFLAGS) -c src/edr_remote_bof.c -o $(BIN)/edr_remote_bof.x86.o $(INCLUDE)

clean:
	rm -f $(BIN)/*.o
