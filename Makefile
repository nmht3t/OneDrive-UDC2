CC = x86_64-w64-mingw32-gcc
PYTHON = python3
CFLAGS = -c -Os -fno-builtin -Wall -Wno-unused-function -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -mno-red-zone
CONFIG_HEADER = client/config.h
CONFIG_GENERATOR = server/genconfig.py
BOF_SRC = client/bof.c
BOF_OBJ = client/bof.o

all: $(BOF_OBJ)

$(CONFIG_HEADER): server/config.json $(CONFIG_GENERATOR)
	$(PYTHON) $(CONFIG_GENERATOR) --config server/config.json --output $(CONFIG_HEADER)

$(BOF_OBJ): $(BOF_SRC) $(CONFIG_HEADER)
	$(CC) $(CFLAGS) $(BOF_SRC) -o $(BOF_OBJ)

clean:
	rm -f $(BOF_OBJ) $(CONFIG_HEADER)

.PHONY: all clean
