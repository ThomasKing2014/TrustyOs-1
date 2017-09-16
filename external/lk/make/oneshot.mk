
-include local.mk
include make/macros.mk
include make/build-flags.mk

# default to no ccache
CCACHE ?=
CC := $(CCACHE) $(TOOLCHAIN_PREFIX)gcc
LD := $(TOOLCHAIN_PREFIX)ld
AR := $(TOOLCHAIN_PREFIX)ar
OBJDUMP := $(TOOLCHAIN_PREFIX)objdump
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy
CPPFILT := $(TOOLCHAIN_PREFIX)c++filt
SIZE := $(TOOLCHAIN_PREFIX)size
NM := $(TOOLCHAIN_PREFIX)nm
STRIP := $(TOOLCHAIN_PREFIX)strip

# try to have the compiler output colorized error messages if available
export GCC_COLORS ?= 1


DEBUG ?= 2
LKINC ?= .
BUILDDIR := $(BUILDROOT)
#GLOBAL_INCLUDES := $(BUILDDIR) $(addsuffix include,$(LKINC))
GLOBAL_INCLUDES := $(BUILDDIR) $(LKINC)

GLOBAL_OPTFLAGS ?= $(ARCH_OPTFLAGS)
GLOBAL_COMPILEFLAGS := -g -fno-builtin -finline -include $(TOPDIR)/headers/config.h
GLOBAL_COMPILEFLAGS += -W -Wall -Wno-multichar -Wno-unused-parameter -Wno-unused-function -Wno-unused-label
GLOBAL_CFLAGS := --std=gnu99 -Werror-implicit-function-declaration -Wstrict-prototypes -Wwrite-strings
#GLOBAL_CFLAGS += -Werror
GLOBAL_CPPFLAGS := -fno-exceptions -fno-rtti -fno-threadsafe-statics
#GLOBAL_CPPFLAGS += -Weffc++
GLOBAL_ASMFLAGS := -DASSEMBLY
GLOBAL_LDFLAGS :=

GLOBAL_LDFLAGS += $(addprefix -L,$(LKINC))

# Architecture specific compile flags
#ARCH_COMPILEFLAGS :=
#ARCH_CFLAGS :=
#ARCH_CPPFLAGS :=
#ARCH_ASMFLAGS :=

# master module object list
ALLOBJS_MODULE :=

# master object list (for dep generation)
ALLOBJS :=

# a linker script needs to be declared in one of the project/target/platform files
# LINKER_SCRIPT :=

# anything you add here will be deleted in make clean
GENERATED := $(CONFIGHEADER)

# anything added to GLOBAL_DEFINES will be put into $(BUILDDIR)/config.h
GLOBAL_DEFINES := LK=1

# Anything added to GLOBAL_SRCDEPS will become a dependency of every source file in the system.
# Useful for header files that may be included by one or more source files.
GLOBAL_SRCDEPS := $(CONFIGHEADER)

# add any external module dependencies
MODULES := $(EXTERNAL_MODULES)

# any .mk specified here will be included before build.mk
# EXTRA_BUILDRULES :=

# any rules you put here will also be built by the system before considered being complete
EXTRA_BUILDDEPS :=

# any rules you put here will be depended on in clean builds
EXTRA_CLEANDEPS :=

# any objects you put here get linked with the final image
#EXTRA_OBJS :=

# any extra linker scripts to be put on the command line
#EXTRA_LINKER_SCRIPTS :=

# if someone defines this, the build id will be pulled into lib/version
BUILDID ?=

# comment out or override if you want to see the full output of each command
NOECHO ?= @

# declared the top level rule
all::

$(eval $(foreach _mod,$(filter-out %:TA,$(M)),include $(_mod)/rules.mk))

TRUSTY_ALL_USER_TASKS += $(subst :TA,,$(filter %:TA,$(M)))

# prefix all of the paths in GLOBAL_INCLUDES with -I
GLOBAL_INCLUDES := $(addprefix -I,$(GLOBAL_INCLUDES))

#$(info prebuilt modules: PREBUILT_OBJS=$(PREBUILT_OBJS))
#$(info building module : ALLMODULE_OBJS=$(ALLMODULE_OBJS))
$(eval ALLMODULE_OBJS += $(PREBUILT_OBJS))

include make/build.mk

all:: $(ALLUSER_TASK_OBJS) $(ALLMODULE_OBJS)

# make all object files depend on any targets in GLOBAL_SRCDEPS
$(ALLOBJS): $(GLOBAL_SRCDEPS)

configheader:

.PHONY: configheader


