cs311cache: main.c 
	gcc -g -O2 $^ -o $@
clean:
	rm -rf *~cs311cache

test: cs311cache test_simple test_gcc test_libquantum

test_simple:
	@echo "Testing simple"; \
        ./cs311cache -c 1024:8:8 -x sample_input/simple | diff -Naur sample_output/simple - ;\
        if [ $$? -eq 0 ]; then echo "\tTest seems correct\n"; else echo "\tResults not identical, check the diff output\n"; fi


test_gcc:
	@echo "Testing gcc"; \
        ./cs311cache -c 1024:8:8 -x sample_input/gcc | diff -Naur sample_output/gcc - ;\
        if [ $$? -eq 0 ]; then echo "\tTest seems correct\n"; else echo "\tResults not identical, check the diff output\n"; fi
	

test_libquantum:
	@echo "Testing libquantum"; \
        ./cs311cache -c 1024:8:8 -x sample_input/libquantum | diff -Naur sample_output/libquantum - ;\
        if [ $$? -eq 0 ]; then echo "\tTest seems correct\n"; else echo "\tResults not identical, check the diff output\n"; fi
	
