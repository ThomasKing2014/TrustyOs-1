
include $(SDK_MAKEROOT)/process.mk

# Add this dummy user task to build all libraries
TRUSTY_ALL_USER_TASKS += $(SDK_MAKEROOT)/lib

$(SDK_BUILDDIR):
	$(call create-folder-if-no-exist,$@)

sdk_setup: $(SDK_BUILDDIR) all
	$(call install-lk-source,$<)
	$(call install-headers,$<,$(GLOBAL_INCLUDES))
	$(call install-prebuilts,$<,,$(SDK_MAKEROOT)/lib,)
	$(call install-pac_tool,$<)
	$(call gen-makefiles,$<)

############################################################
# @@@ Directory structure to be generated @@@
#
# ├── Makefile           -> Root makefile
# ├── headers
# │   ├── external       -> LK header files
# │   │   ├── headers
# │   │   ├── lk
# │   │   └── openssl
# │   ├── lib            -> User lib header files
# │   │   ├── include
# │   │   ├── interface
# │   │   └── lib
# │   ├── lk             -> Trusty header files
# │   │   └── trusty
# │   └── system
# │       ├── gatekeeper
# │       └── keymaster
# ├── lds                -> Linked scripts
# ├── make               -> Make scripts
# ├── prebuilts          -> Prebuild modules to be linked
# │   ├── lib            -> User libraries
# │   └── user_tasks     -> User task elfs
# └── source             -> Make scripts
#     ├── external
#     │   └── lk
#     └── lk
#         └── trusty
############################################################

