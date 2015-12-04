#!/bin/sh
set -x
make
rmmod sys_submitjob
insmod sys_submitjob.ko

rm -f smallFile.txt.out
rm -f video.webm.enc
rm -f video.webm.enc.dec
rm -f video.webm.enc2
rm -f nohup.txt

./encrypt -k 123456 -e smallFile.txt smallFile.txt.out
./encrypt -k 123456 -e video.webm video.webm.enc
./encrypt -k wrongpassword -d video.webm.enc video.webm.enc.dec
./encrypt_no_wait -k 123456 -e video.webm video.webm.enc2
./encrypt_no_wait -k 123456 -e video.webm video.webm.enc2
./QueueCtl -l
./QueueCtl -c
