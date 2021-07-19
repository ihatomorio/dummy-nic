# ターゲットの定義
SRCS = raw_socket.c util.c
OBJ_DIR = .obj/
OBJS = $(patsubst %.c,$(OBJ_DIR)%.o,$(SRCS))
DEPS = $(patsubst %.c,$(OBJ_DIR)%.d,$(SRCS))

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

$(OBJ_DIR)%.o : %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $*.c -o $(OBJ_DIR)$*.o

# cleanルール
.PHONY: clean
clean:
	$(RM) -r $(OBJ_DIR)

# include dependency
-include $(DEPS)
