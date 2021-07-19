# ターゲットの定義
SRCS = dummy-nic.c
OBJ_DIR = .obj/
OBJS = $(OBJ_DIR)$(SRCS:.c=.o)
DEPS = $(OBJ_DIR)$(SRCS:.c=.d)

TARGET = $(OBJ_DIR)dummy-nic
LIBOBJS = lib/$(OBJ_DIR)raw_socket.o

# 定義済みマクロの再定義
CC = gcc
CFLAGS = -MP -MMD -Wall -g

.PHONY: all clean

all: pre-build build

pre-build:
# .obj 作成をこっそりやる
	@ if [ ! -d "$(OBJ_DIR)" ]; then \
		install -d $(OBJ_DIR); \
		fi;
	@make -C lib

# サフィックスルールにより依存ファイルを全てコンパイル
build: $(OBJS) $(TARGET)

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) $(LIBOBJS)
	$(CC) $(LFLAGS) $+ -o $@

# cleanルール
.PHONY: clean
clean:
	$(RM) -r $(OBJ_DIR)

-include $(DEPS)
