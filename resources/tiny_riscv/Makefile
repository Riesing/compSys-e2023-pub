%.riscv: %.c lib.c Makefile
	/opt/riscv/bin/riscv32-unknown-elf-gcc -march=rv32im -mabi=ilp32 -fno-tree-loop-distribute-patterns -mno-relax -O1 $< lib.c -static -nostartfiles -nostdlib -o $@

%.dis: %.riscv Makefile
	/opt/riscv/bin/riscv32-unknown-elf-objdump -s -w $< > $@
	/opt/riscv/bin/riscv32-unknown-elf-objdump -S $< >> $@
