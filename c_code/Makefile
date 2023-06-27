.PHONY: clean fmt

TARGET=test_sve

CC=cc
CFLAGS=-std=c99 -march=armv8-a+sve -Wall -Wextra -pedantic -g -O0
LN_FLAGS=

BUILD_DIR=./build
SRC_DIR=./src

SOURCE = $(wildcard $(SRC_DIR)/*.c)
HEADERS = $(wildcard $(SRC_DIR)/*.h)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SOURCE))

# Gcc/Clang will create these .d files containing dependencies.
DEP = $(OBJECTS:%.o=%.d)

default: $(TARGET)

$(TARGET): $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LN_FLAGS) $^ -o $@

-include $(DEP)

# The potential dependency on header files is covered
# by calling `-include $(DEP)`.
# The -MMD flags additionaly creates a .d file with
# the same name as the .o file.
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -c $< -o $@

test: $(TARGET)
	$(BUILD_DIR)/$(TARGET)

clean:
	rm -rf $(BUILD_DIR)

fmt:
	clang-format --style=file -i $(SOURCE) $(HEADERS)
