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

########## LINUXCLI ############################################################

linux-cli: CFLAGS=-std=gnu99 -pthread -g
linux-cli: LDFLAGS=-L./lib -lbf -lrt
linux-cli: INCLUDE=-I./src/

LINUXCLI_SRCS=$(wildcard ./src/ui/linux-cli/*.c)
LINUXCLI_OBJS=$(LINUXCLI_SRCS:./src/%.c=./obj/%.o)
LINUXCLI_DEPS=$(LINUXCLI_OBJS:%.o=%.d)

./obj/ui/linux-cli/%.o: ./src/ui/linux-cli/%.c 
	@mkdir -p ./obj/ui/linux-cli
	$(CC) -MT $@ -MMD -MP -MF ./obj/ui/linux-cli/$*.d $(INCLUDE) $(CFLAGS) -c $< -o $@

linux-cli: $(LINUXCLI_OBJS) libbf
	@mkdir -p ./bin
	$(CC) $(CFLAGS) $(LINUXCLI_OBJS) -o $(BIN) $(LDFLAGS)

-include $(LINUXCLI_DEPS)

################################################################################

.PHONY: clean
clean:
	@rm -f $(LIBBF_OBJS) $(LIBBF_DEPS) $(LINUXCLI_OBJS) $(LINUXCLI_DEPS) $(BIN) $(LIB)

