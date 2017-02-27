CC=gcc
CFLAGS=-std=gnu99 -pthread -g
DEFS=-D_FILE_OFFSET_BITS=64 -D__USE_BSD
BIN=./bin/bitfiend

LIBBF_SRCS=$(wildcard ./src/libbf/*.c)
LIBBF_OBJS=$(LIBBF_SRCS:./src/%.c=./obj/%.o)
LIBBF_DEPS=$(LIBBF_OBJS:%.o=%.d)

./obj/libbf/%.o: ./src/libbf/%.c 
	@mkdir -p ./obj/libbf
	$(CC) -MT $@ -MMD -MP -MF ./obj/libbf/$*.d $(CFLAGS) $(DEFS) -c $< -o $@

bitfiend: $(LIBBF_OBJS)
	@mkdir -p ./bin
	$(CC) $(CFLAGS) $(DEFS) $(LIBBF_OBJS) -o $(BIN)

-include $(LIBBF_DEPS)

.PHONY: clean
clean:
	@rm $(LIBBF_OBJS) $(LIBBF_DEPS) $(BIN)
