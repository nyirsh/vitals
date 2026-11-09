# Runs either console's Makefile, or both, from the top of the repository:
#   make                  builds both (the PS3, then the Vita)
#   make ps3, make psv    builds that one
#   make clean            runs a command on both; make ps3 clean, make psv test: on that one
# What both have: test clean upload-app log app-log fetch status pull editor plugin ssl http app
# update-certs and preview do the same for both, so they run once.
# What only one has (make ps3 install, make psv browser) needs that console named. Options such as
# DEBUG=1 reach the console's Makefile. It stops at the first failure, so with a console off use
# make ps3 fetch or make psv fetch.

CONSOLES := ps3 psv
SHARED := test clean upload-app log app-log fetch status pull editor plugin ssl http app
ONCE := update-certs preview

CHOSEN := $(filter $(CONSOLES),$(MAKECMDGOALS))
TARGETS := $(or $(CHOSEN),$(CONSOLES))
ACTIONS := $(filter-out $(CONSOLES),$(MAKECMDGOALS))

.DEFAULT_GOAL := all

ifeq ($(CHOSEN),)
ONE_ONLY := $(filter-out all $(SHARED) $(ONCE),$(ACTIONS))
ifneq ($(ONE_ONLY),)
$(error $(ONE_ONLY): not a command both consoles have, so name the console: make ps3 $(firstword $(ONE_ONLY)) or make psv $(firstword $(ONE_ONLY)), whichever has it)
endif
endif

all:
	$(foreach console,$(TARGETS),$(MAKE) -C $(console) &&) true

# A console named alone is built; with a command, the command is what runs
$(CONSOLES):
	$(if $(ACTIONS),@:,$(MAKE) -C $@)

$(ONCE):
	$(MAKE) -C $(firstword $(TARGETS)) $@

EACH := $(filter-out all $(ONCE),$(ACTIONS))
ifneq ($(EACH),)
$(EACH):
	$(foreach console,$(TARGETS),$(MAKE) -C $(console) $@ &&) true
endif

.PHONY: all $(CONSOLES) $(ONCE) $(EACH)
