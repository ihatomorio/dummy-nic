# ターゲットの定義
SRCS = raw_socket.c
OBJ_DIR = .obj/
OBJS = $(OBJ_DIR)$(SRCS:.c=.o)
DEPS = $(OBJ_DIR)$(SRCS:.c=.d)

# 定義済みマクロの再定義
CC = gcc
CFLAGS = -MP -MMD -Wall -g -Werror

.PHONY: all clean

all: pre-build build

pre-build:
# .obj 作成をこっそりやる
	@ if [ ! -d "$(OBJ_DIR)" ]; then \
		install -d $(OBJ_DIR); \
		fi;

# サフィックスルールにより依存ファイルを全てコンパイル
build: $(OBJS)

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -c $< -o $@

# cleanルール
.PHONY: clean
clean:
	$(RM) -r $(OBJ_DIR)

-include $(DEPS)
