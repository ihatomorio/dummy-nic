# ターゲットの定義
OBJS = raw_socket.c

# 定義済みマクロの再定義
CC = gcc
CFLAGS = -MMD -Wall -g

# サフィックスルール: .oファイルは.cファイルに依存している
.SUFFIXES: .c .o

.PHONY: all

# サフィックスルールにより依存ファイルを全てコンパイル
.c.o:
	$(CC) $(CFLAGS) -o .obj/ -c $<

-include .obj/raw_socket.d

# cleanルール
.PHONY: clean
clean:
	$(RM) $(COMMAND) $(OBJS)
