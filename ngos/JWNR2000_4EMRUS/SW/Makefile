#****************************************************************************
#
#  Copyright (c) 2006, Westell, Inc.
#
#****************************************************************************

# This exports all variables to sub-makefiles
.EXPORT_ALL_VARIABLES:

include version.make

BRCM_RELEASETAG=$(BRCM_VERSION).$(BRCM_RELEASE)L.$(BRCM_EXTRAVERSION)

###########################################
#
# Import build settings
#
###########################################

ifeq ($(TARGET),)
ifeq ($(PROFILE),)
$(error PROFILE must be specified)
else
TARGET=$(PROFILE)
endif
endif

ifeq ($(VENDOR),)
$(error VENDOR must be specified)
endif

###########################################
#
# Define Basic Variables
#
###########################################

BUILD_DIR 	= $(shell pwd)
PROFILE_CHECK	= $(BUILD_DIR)/.PROFILE
OLDPROFILE	= $(shell cat $(PROFILE_CHECK))

TARGET_DIR = $(BUILD_DIR)/Westell/targets.$(VENDOR)/$(TARGET)
TARGETS_DIR = $(BUILD_DIR)/Westell/targets.$(VENDOR)

all:
	@echo "making $(@) for $(PROFILE)"
	$(MAKE) -C $(TARGET_DIR) $(@)

$(MAKECMDGOALS):
	@echo "only making: $(MAKECMDGOALS), now making $(@) for $(PROFILE)"
	$(MAKE) -C $(TARGET_DIR) $(@)
