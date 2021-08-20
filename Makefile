REBAR := $(shell which rebar3 2>/dev/null || which ./rebar3)
SUBMODULES = build_utils
SUBTARGETS = $(patsubst %,%/.git,$(SUBMODULES))

SERVICE_NAME = dev
UTILS_PATH := build_utils
TEMPLATES_PATH = .

BUILD_IMAGE_NAME := build-erlang
BUILD_IMAGE_TAG := aaa79c2d6b597f93f5f8b724eecfc31ec2e2a23b

CALL_ANYWHERE := all submodules rebar-update compile lint xref dialyze \
				 test clean distclean check_format format

CALL_W_CONTAINER := $(CALL_ANYWHERE)

.PHONY: $(CALL_W_CONTAINER)

all: compile

-include $(UTILS_PATH)/make_lib/utils_container.mk

$(SUBTARGETS): %/.git: %
	git submodule update --init $<
	touch $@

submodules: $(SUBTARGETS)

compile: submodules rebar-update
	$(REBAR) compile

rebar-update:
	$(REBAR) update

test: submodules
	$(REBAR) eunit

xref: submodules
	$(REBAR) xref

dialyze: submodules
	$(REBAR) dialyzer

clean:
	$(REBAR) clean

distclean:
	$(REBAR) clean -a
	rm -rfv _build

lint:
	$(REBAR) lint

check_format:
	$(REBAR) as test fmt -c

format:
	$(REBAR) fmt -w
