CXX ?= g++
BUILD_DIR ?= build
TARGET := $(BUILD_DIR)/cph_ccse_conformance
SOURCES := src/ccse.cpp src/main.cpp
HEADERS := src/ccse.hpp src/strict_json.hpp
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror
LDLIBS += -lcrypto -ldl
POSITIVE_FIXTURE := ../../ccse/testdata/ccse_v1_ed25519_positive.json
NEGATIVE_FIXTURE := ../../ccse/testdata/ccse_v1_negative.json

.PHONY: all test test-provider-selection test-provisional test-reproducible clean

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -Isrc $(SOURCES) $(LDLIBS) -o $@

test: $(TARGET)
	$(TARGET) $(POSITIVE_FIXTURE) $(NEGATIVE_FIXTURE)

test-provider-selection: $(TARGET)
	scripts/provider-selection-test.sh \
	  $(TARGET) $(POSITIVE_FIXTURE) $(NEGATIVE_FIXTURE)

test-provisional: $(TARGET)
	@set +e; \
	output="$$(env -u CPH_CCSE_ICU_LIBRARY -u CPH_CCSE_ICU_ABI \
	  CPH_CCSE_ALLOW_AMBIENT_ICU=1 \
	  $(TARGET) $(POSITIVE_FIXTURE) $(NEGATIVE_FIXTURE) 2>&1)"; \
	status=$$?; \
	set -e; \
	printf '%s\n' "$$output"; \
	if [ "$$status" -ne 2 ]; then \
	  echo "expected provisional dependency-blocker exit 2, got $$status" >&2; \
	  exit 1; \
	fi; \
	printf '%s\n' "$$output" | grep -F \
	  "Vectors executed: 1 positive, 18 negative" >/dev/null; \
	printf '%s\n' "$$output" | grep -F "[PROVISIONAL]" >/dev/null

test-reproducible:
	@test -n "$(WORK_DIR)" || \
	  { echo "WORK_DIR=/absolute/untracked/workspace-temp is required" >&2; exit 64; }
	scripts/reproducible-test.sh --work-dir "$(WORK_DIR)" $(if $(JOBS),--jobs "$(JOBS)")

clean:
	rm -f $(TARGET)
