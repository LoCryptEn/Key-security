# 指定 OpenSSL 库的路径
OPENSSL_DIR = /opt/openssl

# 指定编译器
CC = gcc

# 指定编译选项
CFLAGS = -I$(OPENSSL_DIR)/include -g -std=c99

# 指定链接选项
LDFLAGS = -L$(OPENSSL_DIR)/lib64 -lssl -lcrypto -lpthread -std=c99

# 目标文件
TARGET = LearnTest_program

# 源文件
SRCS = user.c user_helper.c

# 指定 build 目录
BUILD_DIR = build

# 对象文件
OBJS = $(SRCS:.c=.o)

# 指定对象文件路径
OBJ_FILES = $(addprefix $(BUILD_DIR)/, $(OBJS))

# 默认目标
all: $(BUILD_DIR)/$(TARGET)

# 编译规则
$(BUILD_DIR)/$(TARGET): $(OBJ_FILES)
	$(CC) $(OBJ_FILES) -o $@ $(LDFLAGS)

# 编译源文件
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# 创建 build 目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 清理生成的文件
clean:
	rm -rf $(BUILD_DIR)
