OUTDIR := out
TITLE_ID := 4200000000000666
SD_ROOT := $(OUTDIR)/sd
TITLE_DIR := $(SD_ROOT)/atmosphere/contents/$(TITLE_ID)

export NETWORK_MITM_GIT_BRANCH   := $(shell git symbolic-ref --short HEAD)

ifeq ($(strip $(shell git status --porcelain 2> /dev/null)),)
export NETWORK_MITM_GIT_REVISION := $(NETWORK_MITM_GIT_BRANCH)-$(shell git rev-parse --short HEAD)
else
export NETWORK_MITM_GIT_REVISION := $(NETWORK_MITM_GIT_BRANCH)-$(shell git rev-parse --short HEAD)-dirty
endif

NETWORK_MITM_VERSION_MAJOR := $(shell grep 'define NETWORK_MITM_VERSION_MAJOR\b' network_mitm/include/networkmitm_version.h | tr -s [:blank:] | cut -d' ' -f3)
NETWORK_MITM_VERSION_MINOR := $(shell grep 'define NETWORK_MITM_VERSION_MINOR\b' network_mitm/include/networkmitm_version.h | tr -s [:blank:] | cut -d' ' -f3)
NETWORK_MITM_VERSION_MICRO := $(shell grep 'define NETWORK_MITM_VERSION_MICRO\b' network_mitm/include/networkmitm_version.h | tr -s [:blank:] | cut -d' ' -f3)
NETWORK_MITM_VERSION := $(NETWORK_MITM_VERSION_MAJOR).$(NETWORK_MITM_VERSION_MINOR).$(NETWORK_MITM_VERSION_MICRO)-$(NETWORK_MITM_GIT_REVISION)

all: dist

build:
	make -C Atmosphere-libs/libstratosphere nx_release
	make -C network_mitm all

pack: build
	@mkdir -p $(TITLE_DIR)/flags
	@cp network_mitm/out/nintendo_nx_arm64_armv8a/release/network_mitm.nsp $(TITLE_DIR)/exefs.nsp
	@touch $(TITLE_DIR)/flags/boot2.flag
	@rm -f $(TITLE_DIR)/mitm.lst
	@echo "ssl" >> $(TITLE_DIR)/mitm.lst
	@echo "ssl:s" >> $(TITLE_DIR)/mitm.lst

dist: pack
	@cd $(SD_ROOT); zip -r ../network_mitm-$(NETWORK_MITM_VERSION).zip ./* > /dev/null; cd ../;

clean:
	make -C Atmosphere-libs/libstratosphere clean
	make -C network_mitm clean

.PHONY: all build pack dist clean
