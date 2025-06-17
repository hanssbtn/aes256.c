
CC = gcc

CFLAGS = -Wall -Wextra -fPIC -O3

LIBDIR = lib

OBJDIR = objs

VPATH = . tests

SRC = src/aes256.c

STATIC_LIB_NAME = libaes256.a
ifeq ($(OS),Windows_NT)
    SHARED_LIB_NAME = libaes256.dll
else
    SHARED_LIB_NAME = libaes256.so
endif
STATIC_LIB = $(addprefix $(LIBDIR)/, $(STATIC_LIB_NAME))
SHARED_LIB = $(addprefix $(LIBDIR)/, $(SHARED_LIB_NAME))

all: $(STATIC_LIB) $(SHARED_LIB)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(LIBDIR):
	@mkdir -p $(LIBDIR)

$(OBJDIR)/aes256.o: $(SRC) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(STATIC_LIB): $(OBJDIR)/aes256.o | $(LIBDIR)
	ar rcs $@ $^

$(SHARED_LIB): $(OBJDIR)/aes256.o | $(LIBDIR)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

clean:
	rm -rf objs lib/*

.PHONY: clean