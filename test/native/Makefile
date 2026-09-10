# Host-native test harness for AsyncTCP.
#
#   make -C test/native run      build and run
#   make -C test/native          build only
#   make -C test/native clean
#
# Nothing here needs PlatformIO or an ESP32 toolchain; plain g++ is enough.

ROOT     := $(abspath $(CURDIR)/../..)
SRC_DIR  := $(ROOT)/src
MOCK_DIR := $(CURDIR)/mocks
BUILD    := $(CURDIR)/build
BIN      := $(BUILD)/asynctcp_tests

CXX      ?= g++

# The mock include dir must come FIRST so that "lwip/tcp.h", "Arduino.h",
# "freertos/semphr.h" etc. resolve to the mocks rather than anything else.
INCLUDES := -I$(MOCK_DIR)/include -I$(MOCK_DIR) -I$(SRC_DIR) -I$(CURDIR)

DEFINES := \
  -DASYNCTCP_NATIVE_TEST=1 \
  -DARDUINO=10812 \
  -DCONFIG_LWIP_TCPIP_CORE_LOCKING=1 \
  -DCONFIG_ASYNC_TCP_RUNNING_CORE=-1 \
  -DCONFIG_ASYNC_TCP_USE_WDT=1 \
  -DCONFIG_ASYNC_TCP_TASK_STACK_SIZE=8192 \
  -DCONFIG_ASYNC_TCP_TASK_PRIORITY=3 \
  -DCONFIG_ASYNC_TCP_MAX_ACK_TIME=5000 \
  -DCONFIG_ASYNC_TCP_PRIORITY=10 \
  -DCONFIG_ASYNC_TCP_QUEUE_SIZE=64 \
  -DCONFIG_ASYNC_TCP_STACK_SIZE=8192

# Exceptions must stay ON: the async-task pump unwinds out of the library's
# task loop with one. -fno-rtti matches the library's own build.
CXXFLAGS ?= -std=gnu++17 -g -O0 -fno-rtti -fexceptions -Wall -Wextra \
            -Wno-unused-parameter -Wno-missing-field-initializers -Wno-format

LDFLAGS ?=

# make SANITIZE=1 run  -- address + UB sanitizers.
# Leak detection is off: reset() intentionally reclaims pcbs/pbufs the library
# still points at, and the library's own task/mutex singletons never shut down.
ifeq ($(SANITIZE),1)
CXXFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
BUILD := $(CURDIR)/build-asan
BIN := $(BUILD)/asynctcp_tests
export ASAN_OPTIONS := detect_leaks=0
endif

LIB_SRCS   := $(wildcard $(SRC_DIR)/*.cpp)
MOCK_SRCS  := $(wildcard $(MOCK_DIR)/*.cpp)
TEST_SRCS  := $(wildcard $(CURDIR)/tests/*.cpp) $(CURDIR)/test_main.cpp

ALL_SRCS := $(LIB_SRCS) $(MOCK_SRCS) $(TEST_SRCS)
OBJS     := $(patsubst $(ROOT)/%,$(BUILD)/%.o,$(ALL_SRCS))
DEPS     := $(OBJS:.o=.d)

# Relink when a source file is added or removed, so a deleted test does not
# linger in the binary via its stale object file.
SRCLIST := $(BUILD)/.srclist
$(shell mkdir -p $(BUILD); echo '$(ALL_SRCS)' | cmp -s - $(SRCLIST) || echo '$(ALL_SRCS)' > $(SRCLIST))

.PHONY: all run clean verbose

all: $(BIN)

run: $(BIN)
	@$(BIN)

verbose: $(BIN)
	@ASYNCTCP_TEST_VERBOSE=1 $(BIN)

$(BIN): $(OBJS) $(SRCLIST)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD)/%.o: $(ROOT)/%
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCLUDES) -MMD -MP -c $< -o $@

clean:
	rm -rf $(BUILD)

-include $(DEPS)
