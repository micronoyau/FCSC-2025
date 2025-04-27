CFLAGS += -Wall -Wextra -fPIC -pie -Wl,-z,relro,-z,now -fstack-protector-all
http3: http3.c hpack.c

.PHONY: clean
clean:
	rm -f http3
