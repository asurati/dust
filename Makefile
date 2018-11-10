#
# Copyright (c) 2018 Amol Surati
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Native build: make
# Cross build: make CC=powerpc-linux-gnu-cc LDFLAGS=-static

BIN = dust

CFLAGS += -c -I ./include -MMD -MP -std=c11
CFLAGS += -Wall -Wextra -Werror -Wshadow -Wfatal-errors -pedantic -pedantic-errors
#CFLAGS += -flto
CFLAGS += -fstack-protector-strong
CFLAGS += -g -O0
#CFLAGS += -g -O3 -D_FORTIFY_SOURCE=2

#LDFLAGS += -flto

SRCS  = aead.c bn.c chacha.c ec.c hkdf.c hmac.c limb.c list.c main.c
SRCS += poly1305.c rndm.c sha2.c tls.c
DEPS  = $(SRCS:.c=.d)
OBJS  = $(SRCS:.c=.o)

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

-include $(DEPS)

c:
	rm -f $(BIN) $(OBJS) $(DEPS)
r:
	@./$(BIN)

.PHONY: all c r
