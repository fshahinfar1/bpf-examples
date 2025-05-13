#! /bin/bash
 sudo taskset -c 2,3,4 \
	 ./xdpsock -l \
	 -i $NET_IFACE -q 0 \
	 -z -N \
	 -m -u \
	 --xdp ./xdpsock_kern.o \
	 -n 1

