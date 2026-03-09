# ============================================================
# VMP 工具链 Makefile (macOS + Android NDK)
# make all    → 编译 C stub → 嵌入 Go → 输出到 build/
# make stub   → 仅编译 VM 解释器 blob
# make packer → 仅编译 Go packer（需先 make stub）
# make gui    → 编译 GUI 版本
# make demo   → 交叉编译 demo 程序
# make test   → 运行 Go 单元测试
# make clean  → 清理所有产物
# ============================================================

# Android NDK 配置
NDK       ?= $(HOME)/Library/Android/sdk/ndk/21.1.6352462
TOOLCHAIN  = $(NDK)/toolchains/llvm/prebuilt/darwin-x86_64
API        = 21

# 交叉编译工具链 (使用 NDK 的 clang)
CC         = $(TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
LD         = $(TOOLCHAIN)/bin/aarch64-linux-android-ld
OBJCOPY    = $(TOOLCHAIN)/bin/aarch64-linux-android-objcopy
NM         = $(TOOLCHAIN)/bin/aarch64-linux-android-nm
GO         = go

# 目录
STUB_DIR   = stub
CMD_DIR    = cmd/vmpacker
DEMO_DIR   = demo
BUILD_DIR  = build

# ------ VM 解释器 blob ------
STUB_SRC   = $(STUB_DIR)/vm_interp_clean.c
STUB_LDS   = $(STUB_DIR)/vm_interp.lds
STUB_O     = $(BUILD_DIR)/stub/vm_interp.o
STUB_ELF   = $(BUILD_DIR)/stub/vm_interp.elf
STUB_BIN   = $(CMD_DIR)/vm_interp.bin

# ------ Go packer ------
PACKER     = $(BUILD_DIR)/vmpacker

# ------ Demo ------
DEMO_LICENSE     = $(BUILD_DIR)/demo_license
DEMO_SIMPLE      = $(BUILD_DIR)/demo_simple

# 编译选项 (必须 -mcmodel=tiny，禁止 -fPIC)
STUB_CFLAGS = -c -Os -mcmodel=tiny -fno-stack-protector \
              -fno-builtin -nostdlib -march=armv8-a \
              -DVM_INDIRECT_DISPATCH -DVM_FUNC_SPLIT -DVM_TOKEN_ENTRY

DEMO_CFLAGS = -static -O0 -march=armv8-a

# ============================================================
.PHONY: all stub packer demo test clean help

all: stub packer
	@echo ""
	@echo "[+] Build complete: $(BUILD_DIR)/"

# ------ VM 解释器 blob ------
stub: $(STUB_BIN)

$(STUB_O): $(STUB_SRC) | $(BUILD_DIR)/stub
	$(CC) $(STUB_CFLAGS) -o $@ $<

$(STUB_ELF): $(STUB_O) $(STUB_LDS)
	$(LD) -T $(STUB_LDS) -o $@ $<

$(STUB_BIN): $(STUB_ELF) | $(BUILD_DIR)
	$(OBJCOPY) -O binary $< $(BUILD_DIR)/vm_interp_raw.bin
	@echo "Extracting symbol offsets..."
	@OFF1=$$($(NM) $< | grep '\bvm_entry$$' | awk '{print $$1}'); \
	OFF2=$$($(NM) $< | grep '\bvm_entry_token$$' | awk '{print $$1}'); \
	OFF3=$$($(NM) $< | grep '\b_token_table_va$$' | awk '{print $$1}'); \
	if [ -z "$$OFF1" ]; then echo "Error: vm_entry not found"; exit 1; fi; \
	if [ -z "$$OFF2" ]; then echo "Error: vm_entry_token not found"; exit 1; fi; \
	if [ -z "$$OFF3" ]; then echo "Error: _token_table_va not found"; exit 1; fi; \
	echo "  vm_entry=0x$$OFF1 vm_entry_token=0x$$OFF2 _token_table_va=0x$$OFF3"; \
	perl -e 'print pack("Q<", hex($$ARGV[0]))' "0x$$OFF1" > $(BUILD_DIR)/off1.bin; \
	perl -e 'print pack("Q<", hex($$ARGV[0]))' "0x$$OFF2" > $(BUILD_DIR)/off2.bin; \
	perl -e 'print pack("Q<", hex($$ARGV[0]))' "0x$$OFF3" > $(BUILD_DIR)/off3.bin; \
	cat $(BUILD_DIR)/off1.bin $(BUILD_DIR)/off2.bin $(BUILD_DIR)/off3.bin $(BUILD_DIR)/vm_interp_raw.bin > $@; \
	rm -f $(BUILD_DIR)/off1.bin $(BUILD_DIR)/off2.bin $(BUILD_DIR)/off3.bin; \
	echo "[+] vm_interp.bin: $$(stat -f%z $@) bytes (vm_entry=0x$$OFF1 vm_entry_token=0x$$OFF2 _token_table_va=0x$$OFF3)"
	@cp $@ $(BUILD_DIR)/vm_interp.bin

# ------ Go packer (embed vm_interp.bin) ------
packer: $(STUB_BIN) | $(BUILD_DIR)
	@rm -f $(PACKER)
	$(GO) build -o $(PACKER) ./$(CMD_DIR)/
	@echo "[+] packer: $(PACKER)"

# ------ GUI 版本 (Wails + NSIS) ------
GUI_DIR = vmp-gui

gui: stub
	@cp -f "$(STUB_BIN)" "$(GUI_DIR)/backend/api/vm_interp.bin"
	@cd "$(GUI_DIR)" && \
		echo "Building for current platform..." && \
		~/go/bin/wails build
	@echo "[+] GUI built for current platform"
	
# ------ Demo 程序 ------
demo: $(DEMO_LICENSE) $(DEMO_SIMPLE)

$(DEMO_LICENSE): $(DEMO_DIR)/demo_license.c | $(BUILD_DIR)
	$(CC) $(DEMO_CFLAGS) -o $@ $<
	@echo "[+] demo: $@"

$(DEMO_SIMPLE): $(DEMO_DIR)/demo_simple.c | $(BUILD_DIR)
	$(CC) -static -O1 -nostdlib -march=armv8-a -o $@ $<
	@echo "[+] demo: $@"

# ------ 测试 ------
test:
	$(GO) test ./...

# ------ 目录创建 ------
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/stub: | $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/stub

# ------ 清理 ------
clean:
	rm -rf $(BUILD_DIR) $(STUB_BIN)
	@echo "[+] cleaned"

# ------ 帮助 ------
help:
	@echo "make all     - 编译 stub + packer (输出到 build/)"
	@echo "make stub    - 仅编译 VM 解释器 blob"
	@echo "make packer  - 编译 Go packer (自动嵌入 blob)"
	@echo "make gui     - 编译 GUI 版本"
	@echo "make demo    - 交叉编译 demo 程序"
	@echo "make test    - 运行单元测试"
	@echo "make clean   - 清理所有产物"