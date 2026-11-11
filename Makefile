# Runs either console's Makefile, or both, and the RPCS3 installers', from the top of the repository:
#   make                  builds both (the PS3, then the Vita), then the RPCS3 installers (rpcs3/)
#   make ps3, make psv    builds that one; make rpcs3, the RPCS3 installers (with the PS3 app they carry)
#   make clean            runs a command on both; make ps3 clean, make psv test: on that one. Of the
#                         commands, rpcs3/ has only clean, which make clean runs there too
# What both have: test clean upload-app log app-log fetch status pull editor plugin ssl http app
# update-certs and preview do the same for both, so they run once. make art redraws both apps' art
# (shared/tools/make_app_art.py).
# What only one has (make ps3 install, make psv browser) needs that console named. Options such as
# DEBUG=1 reach the console's Makefile. It stops at the first failure, so with a console off use
# make ps3 fetch or make psv fetch.

CONSOLES := ps3 psv
# rpcs3/ builds, and cleans, but has none of the consoles' other commands
PROJECTS := $(CONSOLES) rpcs3
RPCS3_ACTIONS := clean
SHARED := test clean upload-app log app-log fetch status pull editor plugin ssl http app
ONCE := update-certs preview

CHOSEN := $(filter $(PROJECTS),$(MAKECMDGOALS))
TARGETS := $(or $(CHOSEN),$(PROJECTS))
ACTIONS := $(filter-out $(PROJECTS),$(MAKECMDGOALS))

.DEFAULT_GOAL := all

ifeq ($(CHOSEN),)
ONE_ONLY := $(filter-out all art $(SHARED) $(ONCE),$(ACTIONS))
ifneq ($(ONE_ONLY),)
$(error $(ONE_ONLY): not a command both consoles have, so name the console: make ps3 $(firstword $(ONE_ONLY)) or make psv $(firstword $(ONE_ONLY)), whichever has it)
endif
endif

ifeq ($(CHOSEN),rpcs3)
RPCS3_ONLY := $(filter-out all $(RPCS3_ACTIONS),$(ACTIONS))
ifneq ($(RPCS3_ONLY),)
$(error $(RPCS3_ONLY): rpcs3/ only builds and cleans (make rpcs3, make rpcs3 clean))
endif
endif

all:
	$(foreach project,$(TARGETS),$(MAKE) -C $(project) &&) true

# A project named alone is built; with a command, the command is what runs
$(PROJECTS):
	$(if $(ACTIONS),@:,$(MAKE) -C $@)

$(ONCE):
	$(MAKE) -C $(firstword $(filter $(CONSOLES),$(TARGETS)) ps3) $@

EACH := $(filter-out all art $(ONCE),$(ACTIONS))
ifneq ($(EACH),)
$(EACH):
	$(foreach project,$(TARGETS),$(if $(filter rpcs3,$(project)),$(if $(filter $@,$(RPCS3_ACTIONS)),$(MAKE) -C $(project) $@ &&),$(MAKE) -C $(project) $@ &&)) true
endif

# Both apps' art, from one design: run it, then review and commit the images
art:
	python3 shared/tools/make_app_art.py

.PHONY: all art $(PROJECTS) $(ONCE) $(EACH)
