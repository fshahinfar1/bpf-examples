#!/bin/bash

# generating load:  sudo ./build/app -a $NET_PCI --lcores 0@(2,4) -- --client --ip-local 192.168.1.2 --ip-dest 192.168.1.1 --no-arp


mode=single_queue
cores=( 2 4 6 8 10 )
max_cores=${#cores[@]}

num_cores=1
delay=0
xdp_prog=./xdpsock_kern.o # xdp program to load
qid=0 # queue to attach to

while [ $# -gt 0 ]; do
	key=$1
	case $key in 
		-c|--cores)
			num_cores=$2
			shift
			shift
			;;
		-d|--delay)
			delay=$2
			shift
			shift
			;;
		*)
			echo "Unexpected argument"
			exit 1
			;;
	esac
done

echo "Runing experiment: $mode with $num_cores workers"
case $mode in
	single_queue)
		arg_cores=""
		for i in $(seq 0 $((num_cores-1)) );do
			arg_cores="$arg_cores -i $NET_IFACE -q $qid -c ${cores[$i]}"
		done
		cmd="sudo ./xsk_fwd -b 131072 -x $xdp_prog $arg_cores -d $delay"
		echo $cmd
		$cmd
		;;
	*)
		echo Unsuported mode
		exit 1
		;;
esac

echo Done
