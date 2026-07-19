# Compatibility wrapper around the CMake build. CMakeLists.txt is the single
# source of truth; these targets preserve the project's established commands.

CMAKE ?= cmake
N ?= 4
W ?= 16
SEC ?= 128
BENCH_ITERS ?= 100
PIPELINE_ITERS ?= 100
BUILD_DIR = build/n$(N)-w$(W)-sec$(SEC)
BENCH_NS := 4 8 16 32 64

CMAKE_CONFIGURE = $(CMAKE) -S . -B $(BUILD_DIR) \
	-DBLIND_MSS_N=$(N) \
	-DBLIND_MSS_GRIND_W=$(W) \
	-DBLIND_MSS_SEC=$(SEC) \
	-DBLIND_MSS_BENCH_ITERS=$(BENCH_ITERS) \
	-DBLIND_MSS_PIPELINE_ITERS=$(PIPELINE_ITERS) \
	$(CMAKE_ARGS)

.PHONY: all lib test bench bench-bin bench-pipeline configure clean help _bench-build

all: lib

configure:
	$(CMAKE_CONFIGURE)

lib: configure
	$(CMAKE) --build $(BUILD_DIR) --target blindmss --parallel

test: configure
	$(CMAKE) --build $(BUILD_DIR) --target check --parallel

_bench-build: configure
	$(CMAKE) --build $(BUILD_DIR) --target bench_bin --parallel

bench-bin: _bench-build

# Run the full benchmark for the historical N = 4,8,16,32,64 matrix.
bench:
	@$(MAKE) --no-print-directory N=4 _bench-build
	@build/n4-w$(W)-sec$(SEC)/bench_bin --header
	@for n in $(BENCH_NS); do \
		$(MAKE) --no-print-directory N=$$n _bench-build; \
		build/n$$n-w$(W)-sec$(SEC)/bench_bin; \
	done

bench-pipeline: configure
	$(CMAKE) --build $(BUILD_DIR) --target bench_pipeline_bin --parallel
	$(BUILD_DIR)/bench_pipeline_bin

clean:
	$(CMAKE) -E remove_directory build

help:
	@echo "Usage: make <target> [N=<N>] [W=<W>] [SEC=<128|256>]"
	@echo
	@echo "Targets:"
	@echo "  make            Build libblindmss.a"
	@echo "  test            Build and run the regression suite"
	@echo "  bench           Benchmark N = 4,8,16,32,64"
	@echo "  bench-bin       Build one benchmark executable"
	@echo "  bench-pipeline  Run the full-pipeline benchmark"
	@echo "  clean           Remove the CMake build tree"
	@echo
	@echo "Options:"
	@echo "  N=<N>           Parties: 4,8,...,32,64,128,256 (default 4)"
	@echo "  W=<W>           Grinding bits: 0,16,24 (default 16)"
	@echo "  SEC=<128|256>   Security target (default 128)"
	@echo "  CMAKE_ARGS=...  Additional CMake configuration arguments"
