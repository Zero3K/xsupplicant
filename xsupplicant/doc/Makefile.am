EXTRA_DIST=README.certificates README.direct_radius README.wpa Doxyfile.in standards code-design ldp-dsssl xsupplicant_mac_os_x_with_eap_fast_how_to Xsupplicant-wireless-cards.html xml-userguide builddocs.sh

SOURCE_DIRS = ../src ../lib ../tools
SOURCE_FILES = $(shell find $(SOURCE_DIRS) -name "*.c")
HEADER_FILES = $(shell find $(SOURCE_DIRS) -name "*.h")

BUILDDOCS=./builddocs.sh

all-docs: refman userguide

clean-local:
	$(RM) -r refman
	$(RM) -r html
	$(RM) -r pdf
	$(RM) -r txt

userguide: 
	$(BUILDDOCS)

refman: Doxyfile $(SOURCE_FILES) $(HEADER_FILES)
	doxygen
