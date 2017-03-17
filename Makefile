CC=gcc
AR=ar
BIN=./bin/bitfiend
LIB=./lib/libbf.a

########## LIBBF ###############################################################

libbf: CFLAGS=-std=gnu99 -g
libbf: DEFS=-D_FILE_OFFSET_BITS=64 -D__USE_BSD -D_GNU_SOURCE

LIBBF_SRCS=$(wildcard ./src/libbf/*.c)
LIBBF_OBJS=$(LIBBF_SRCS:./src/%.c=./obj/%.o)
LIBBF_DEPS=$(LIBBF_OBJS:%.o=%.d)

./obj/libbf/%.o: ./src/libbf/%.c 
	@mkdir -p ./obj/libbf
	$(CC) -MT $@ -MMD -MP -MF ./obj/libbf/$*.d $(CFLAGS) $(DEFS) -c $< -o $@

libbf: $(LIBBF_OBJS)
	@mkdir -p ./lib
	$(AR) rcs $(LIB) $(LIBBF_OBJS)

-include $(LIBBF_DEPS)

########## CLI #################################################################

bfcli: CFLAGS=-std=gnu99 -pthread -g
bfcli: LDFLAGS=-L./lib -lbf -lrt
bfcli: INCLUDE=-I./src/

BFCLI_SRCS=$(wildcard ./src/ui/cli/*.c)
BFCLI_OBJS=$(BFCLI_SRCS:./src/%.c=./obj/%.o)
BFCLI_DEPS=$(BFCLI_OBJS:%.o=%.d)

./obj/ui/cli/%.o: ./src/ui/cli/%.c 
	@mkdir -p ./obj/ui/cli
	$(CC) -MT $@ -MMD -MP -MF ./obj/ui/cli/$*.d $(INCLUDE) $(CFLAGS) -c $< -o $@

bfcli: $(BFCLI_OBJS) libbf
	@mkdir -p ./bin
	$(CC) $(CFLAGS) $(BFCLI_OBJS) -o $(BIN) $(LDFLAGS)

-include $(BFCLI_DEPS)

################################################################################

.PHONY: clean
clean:
	@rm -f $(LIBBF_OBJS) $(LIBBF_DEPS) $(BFCLI_OBJS) $(BFCLI_DEPS) $(BIN) $(LIB)

