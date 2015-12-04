obj-m += sys_submitjob.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: submitjob encrypt QueueCtl encrypt_no_wait

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
encrypt:encrypt.c
	gcc -Wall -Werror encrypt.c -o encrypt -lcrypto
encrypt_no_wait:encrypt_no_wait.c
	gcc -Wall -Werror encrypt_no_wait.c -o encrypt_no_wait -lcrypto
QueueCtl:QueueCtl.c
	gcc -Wall -Werror QueueCtl.c -o QueueCtl

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xhw1
