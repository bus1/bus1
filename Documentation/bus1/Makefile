DOCS := \
	bus1.xml

XMLFILES := $(addprefix $(obj)/,$(DOCS))
MANFILES := $(patsubst %.xml, %.7, $(XMLFILES))
HTMLFILES := $(patsubst %.xml, %.html, $(XMLFILES))

XMLTO_ARGS := \
	-m $(srctree)/$(src)/stylesheet.xsl \
	--skip-validation \
	--stringparam funcsynopsis.style=ansi \
	--stringparam man.output.quietly=1 \
	--stringparam man.authors.section.enabled=0 \
	--stringparam man.copyright.section.enabled=0

quiet_cmd_db2man = MAN     $@
      cmd_db2man = xmlto man $(XMLTO_ARGS) -o $(obj) $<
%.7: %.xml
	@(which xmlto > /dev/null 2>&1) || \
	 (echo "*** You need to install xmlto ***"; \
	  exit 1)
	$(call cmd,db2man)

quiet_cmd_db2html = HTML    $@
      cmd_db2html = xmlto html-nochunks $(XMLTO_ARGS) -o $(obj) $<
%.html: %.xml
	@(which xmlto > /dev/null 2>&1) || \
	 (echo "*** You need to install xmlto ***"; \
	  exit 1)
	$(call cmd,db2html)

mandocs: $(MANFILES)

htmldocs: $(HTMLFILES)

clean-files := $(MANFILES) $(HTMLFILES)
