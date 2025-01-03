all: bpf

bpf: my_bpf.yy.c my_bpf.tab.c
	gcc -o $@ -g3 $^

%.yy.c: %.l
	flex -o $@ $<

%.tab.c: %.y
	bison -d $<

.PHONY: clean
clean:
	rm -f my_bpf.yy.c my_bpf.tab.c my_bpf.tab.h bpf
