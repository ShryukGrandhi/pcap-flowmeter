PERL ?= perl

.PHONY: test bench bench-quick check demo

test:
	prove -l -r t

check:
	@for f in lib/PcapFlow/*.pm bin/* bench/bench.pl; do $(PERL) -Ilib -wc $$f || exit 1; done

bench:
	$(PERL) bench/bench.pl

bench-quick:
	$(PERL) bench/bench.pl --quick

demo:
	$(PERL) bin/pcapgen --flows 500 -o /tmp/pcapflow-demo.pcap
	$(PERL) bin/pcapflow -t /tmp/pcapflow-demo.pcap
