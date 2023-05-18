APP = hello

CLANG ?= clang
CFLAGS := -g -O2 -Wall -std=c99

LIBS = -ltss2-fapi

HELLO_SRC = hello.c

.PHONY: all
all: $(APP)

hello: $(HELLO_SRC)
	$(CLANG) $(CFLAGS) -o $@ $^ $(LIBS)

.PHONY: clean
clean:
	rm -rf $(APP)