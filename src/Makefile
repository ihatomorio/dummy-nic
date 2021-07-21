# ターゲットの定義
SRCS = dummy-nic.c
OBJ_DIR = .obj/
OBJS = $(patsubst %.c,$(OBJ_DIR)%.o,$(SRCS))
DEPS = $(patsubst %.c,$(OBJ_DIR)%.d,$(SRCS))

TARGET = $(OBJ_DIR)dummy-nic
LIBOBJS = lib/$(OBJ_DIR)raw_socket.o lib/$(OBJ_DIR)util.o lib/$(OBJ_DIR)packet_handler.o lib/handler/$(OBJ_DIR)arp.o lib/handler/$(OBJ_DIR)icmp.o

# 定義済みマクロの再定義
CC = gcc
CFLAGS = -MP -MMD -Wall -g -Werror
LDFLAGS = -lc

.PHONY: all clean

all: pre-build build post-build

pre-build:
# .obj 作成をこっそりやる
	@ if [ ! -d "$(OBJ_DIR)" ]; then \
		install -d $(OBJ_DIR); \
		fi;
	@make -C lib

# サフィックスルールにより依存ファイルを全てコンパイル
build: $(OBJS) $(TARGET)

$(OBJ_DIR)%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $*.c -o $(OBJ_DIR)$*.o

$(TARGET): $(OBJS) $(LIBOBJS)
	$(CC) $(LDFLAGS) $+ -o $@

post-build:
	@sudo chown root $(TARGET)
	@sudo chmod u+s $(TARGET)

# cleanルール
.PHONY: clean
clean:
	make clean -C lib
	$(RM) -r $(OBJ_DIR)

# include dependency
-include $(DEPS)
