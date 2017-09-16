include $(SDK_MAKEROOT)/source_blacklist.mk
include $(SDK_MAKEROOT)/header_blacklist.mk
include $(SDK_MAKEROOT)/module_whitelist.mk
include $(SDK_MAKEROOT)/library_list.mk
include $(SDK_MAKEROOT)/usertask_blacklist.mk
include $(SDK_MAKEROOT)/version.mk

# Define the path of SDK output sub directories
SDK_PATH_MAKE      := make
SDK_PATH_HEADER    := headers
SDK_PATH_PREBUILT  := prebuilts
SDK_PATH_LDS       := lds
SDK_PATH_SOURCE    := source
SDK_PATH_TOOL       := tool

############################################################
# Function: create a folder if it doesn't exist
# $(1): the folder which will be created
define create-folder-if-no-exist
$(if $(wildcard $(1)),,$(shell mkdir -p $(1)))
endef

# Function: find the files with file name patterns
# $(1): file name patterns, as find with '-name'
# $(2): the base dir
############################################################
define find-files-in-list
$(sort $(patsubst ./%,%, \
    $(shell find $(2) -name '$(firstword $(1))' \
      $(foreach _ff,$(1),-o -name '$(_ff)') -and -not -name ".*") \
))
endef

############################################################
# Function: filter out the absent files from a given file list
# $(1): the file list which will be checked
# Return: the filtered file list
define filter-out-path-no-exist
$(sort \
  $(eval _fp :=) \
  $(eval _all := $(subst $(BUILDROOT),,$(1))) \
  $(foreach p,$(_all),$(if $(wildcard $(p)),$(eval _fp += $(p)),)) \
  $(_fp) \
)
endef

############################################################
# Function: filter out the files in blacklist from a given
#           file list
# $(1): the blacklist
# $(2): the header file list to be filtered
# Return: the header file list that has been filtered
define filter-out-blacklist
$(filter-out $(addprefix %,$(1)) $(addsuffix %,$(1)),$(2))
endef

############################################################
# Function: copy header files
# $(1): the header file paths which will not be exported to SDK
# $(2): the header file paths with prefix '-I'
define install-headers
$(eval _header_path := $(1)/$(SDK_PATH_HEADER))
$(info SDK: installing header to $(_header_path)..)

$(eval _installed := $(call filter-out-path-no-exist,$(subst -I,,$(2))))
$(eval INSTALLED_HEADERS := $(call filter-out-blacklist,$(EXCLUDED_HEADERS),$(_installed)))

$(eval INSTALLED_LIB_HEADERS := $(foreach _header,$(INCLUDED_LIB_HEADERS), \
                                  $(call find-files-in-list,include,$(_header))))

$(eval _installed := $(sort $(INSTALLED_HEADERS) $(INSTALLED_LIB_HEADERS)))

$(call create-folder-if-no-exist,$(_header_path))
$(foreach _e,$(_installed),$(info copying $(_e)) \
  $(shell cp -r --parents $(_e) $(_header_path)) \
)

$(shell cp $(CONFIGHEADER) $(_header_path); \
  sed -i '1,2d;$$d;3 i\#pragma once' $(_header_path)/$(notdir $(CONFIGHEADER)) \
)

endef

# Refer to Android NDK: ndk/build/core/default-build-commands.mk
STRIP_TRUSTY_SDK := $(TOOLCHAIN_PREFIX)strip --strip-unneeded
############################################################
# Function: copy prebuilt files
# $(1): the path of prebuilt files
# $(2): the prebuilt file list
# $(3): user-task library name
define install-prebuilts
$(eval _prebuilt_path := $(1)/$(SDK_PATH_PREBUILT))
$(info SDK: installing prebuilts to $(_prebuilt_path)..)

$(eval _installed := $(call filter-out-blacklist,$(EXCLUDED_PREBUILTS),$(2)))
$(eval INSTALLED_PREBUILTS := $(_installed))
$(call create-folder-if-no-exist,$(_prebuilt_path))
$(foreach _e,$(_installed),$(info copying $(_e)) \
  $(shell cp $(_e) $(_prebuilt_path)) \
  $(shell $(STRIP_TRUSTY_SDK) $(_prebuilt_path)/$(notdir $(_e))) \
)

$(eval _installed := \
  $(call find-files-in-list,\
    $(addprefix *,$(LIBRARY_FORMAT_INCLUDED)),$(BUILDDIR)/user_tasks/$(3)) \
)

$(eval _installed := $(filter-out %/$(3).mod.o,$(_installed)))
$(call create-folder-if-no-exist,$(_prebuilt_path)/lib)
$(foreach _e,$(_installed),$(info copying $(_e)) \
  $(eval _ren := $(_e:%.a=%.o))
  $(shell cp $(_e) $(_prebuilt_path)/lib/$(notdir $(_ren)) ) \
  $(shell $(STRIP_TRUSTY_SDK) $(_prebuilt_path)/lib/$(notdir $(_ren)) ) \
)

endef

############################################################
# Function: copy linked scripts
define install-link-scripts
$(eval _lds_path := $(1)/$(SDK_PATH_LDS))
$(info SDK: installing link scripts to $(_lds_path)..)

$(call create-folder-if-no-exist,$(_lds_path))
$(eval INSTALLED_LINKER_SCRIPT := $(2))
$(eval INSTALLED_EXTRA_LINKER_SCRIPTS := $(3))

$(foreach _e,$(2) $(3),$(info copying $(_e)) \
  $(shell cp $(_e) $(_lds_path)) \
)
endef

############################################################
# Function: copy LK source code
# $(1): the base path of source code
define install-lk-source
$(eval _source_path := $(1)/$(SDK_PATH_SOURCE))
$(info SDK: install lk source to $(_source_path)..)

$(call create-folder-if-no-exist,$(_source_path))
$(shell find $(INCLUDED_PATH) \
  $(foreach _folder,$(EXCLUDED_SOURCE),-path *$(_folder)* -prune -o) \
    -type f -print|xargs -I {} cp --parents {} $(_source_path))
endef

############################################################
# Function: copy mktosimg tool
# $(1): the base path of mktosimg pac-tool
define install-pac_tool
$(eval _bin_path := $(1)/$(SDK_PATH_TOOL))
$(info SDK: install pac tool to $(_bin_path)..)

$(call create-folder-if-no-exist,$(_bin_path))
$(shell cp $(SDK_MAKEROOT)/../mktosimg/mktosimg $(_bin_path))
endef

############################################################
# Function: generate makefiles
# $(1): the TOP dir of makefile
# $(2): the path of make scripts
define gen-makefiles
$(eval _make_path := $(1)/$(SDK_PATH_MAKE))
$(info SDK: generate makefiles in $(_make_path)..)

$(call create-folder-if-no-exist,$(_make_path))
$(shell echo '
\nLKINC ?=
\\$(subst \ ,\,$(foreach _e,$(INSTALLED_HEADERS),\n  $(SDK_PATH_HEADER)/$(_e) \\))
\n
\nLIB_INCLUDES ?=
\\$(subst \ ,\,$(foreach _e,$(INSTALLED_LIB_HEADERS),\n  $(SDK_PATH_HEADER)/$(_e) \\))
\n
\nEXTRA_BUILDRULES := $(sort $(addprefix $(SDK_PATH_MAKE)/,$(notdir $(EXTRA_BUILDRULES))))
\n
\nGLOBAL_OPTFLAGS   := $(GLOBAL_OPTFLAGS)
\nARCH              := $(TRUSTY_USER_ARCH)
\nARCH_$(TRUSTY_USER_ARCH)_COMPILEFLAGS := $(ARCH_$(TRUSTY_USER_ARCH)_COMPILEFLAGS)
\nARCH_COMPILEFLAGS := $(ARCH_$(TRUSTY_USER_ARCH)_COMPILEFLAGS)
\nTHUMBCFLAGS       := $(THUMBCFLAGS) $(THUMBINTERWORK)
\nWITH_LINKER_GC    := 1
\nLIBGCC := $$(shell $$(TOOLCHAIN_PREFIX)gcc $$(GLOBAL_COMPILEFLAGS) $$(ARCH_COMPILEFLAGS) $$(THUMBCFLAGS) -print-libgcc-file-name)
\n
\nTRUSTY_USER_ARCH := $(TRUSTY_USER_ARCH)
\n
\nARCH_$$(ARCH)_TOOLCHAIN_PREFIX := $$(TOOLCHAIN_PREFIX)
\nexport ARCH_$$(ARCH)_TOOLCHAIN_PREFIX
\n
' > $(_make_path)/build-flags.mk \
)

$(shell cp $(filter $(addprefix %/,$(EXTRA_BUILDRULES)),$(realpath $(MAKEFILE_LIST))) $(_make_path))

$(shell cp $(lastword $(filter %/xbin.mk,$(realpath $(MAKEFILE_LIST)))) $(_make_path); \
  sed -i '/toolchain.mk/s/^/# /' $(_make_path)/xbin.mk; \
  sed -i 's/-I,$$(GLOBAL_INCLUDES)/-I,$$(GLOBAL_INCLUDES) $$(LIB_INCLUDES)/' $(_make_path)/xbin.mk \
)

$(shell echo '
\nMODULE_DEPS_STATIC +=  version
\n
\nMODULE_DEPS_STATIC := $$(addsuffix .mod.o,$$(addprefix $(SDK_PATH_PREBUILT)/lib/,$$(MODULE_DEPS_STATIC)))
\nMODULE_DEPS_STATIC += $(addprefix $(SDK_PATH_PREBUILT)/lib/,crtbegin.o crtend.o)
' > $(_make_path)/module-user_task.mk
)

$(shell echo '
\nTOOLCHAIN_PREFIX ?= arm-eabi-
\nLKROOT     ?= $(SDK_PATH_SOURCE)/external/lk
\nTOPDIR     := $$(shell pwd)
\nMAKEINC    := $$(LKROOT) $(SDK_PATH_SOURCE)/lk/trusty
\nBUILDROOT  ?= ./build
\n
\nexport TOPDIR
\nexport TOOLCHAIN_PREFIX
\nexport BUILDROOT
\n
\n$$(MAKECMDGOALS) _top:
\n	make -C $$(TOPDIR) -f $$(LKROOT)/make/oneshot.mk $$(addprefix -I, $$(MAKEINC)) $$(MAKECMDGOALS)
' > $(1)/Makefile \
)
endef
