SUBDIRS= os/mod
OBJS += os/netlink.o os/nfq.o os/rand.o os/snd_linux.o os/net.o
OSLIBS= -ldl -lnfnetlink -lnetfilter_queue

$(ETCINIT)/%: os/%
	install $< $@

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(TARGET)
