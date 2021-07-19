# ターゲットの定義
SRCS = raw_socket.c util.c
OBJ_DIR = .obj/
OBJS = $(OBJ_DIR)raw_socket.o $(OBJ_DIR)util.o
DEPS = $(OBJ_DIR)raw_socket.d $(OBJ_DIR)util.d

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

$(OBJ_DIR)raw_socket.o: raw_socket.c util.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)util.o: util.c util.h
	$(CC) $(CFLAGS) -c $< -o $@

# cleanルール
.PHONY: clean
clean:
	$(RM) -r $(OBJ_DIR)

-include $(DEPS)
