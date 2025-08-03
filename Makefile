all: libbpf.so test_bpf

libbpf.so: bpf_syntax.yy.c bpf_syntax.tab.c bpf_ast.c bpf_instrin.c bpf_program.c
	gcc -o $@ -fPIC -shared -g3 $^

test_bpf: main.c libbpf.so
	gcc -o $@ $< -L. -lbpf -g3

%.yy.c: %.l
	flex -o $@ $<

%.tab.c: %.y
	bison -d $<

.PHONY: clean
clean:
	rm -f bpf_syntax.yy.c bpf_syntax.tab.c bpf_syntax.tab.h bpf test_bpf libbpf.so
