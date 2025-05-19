#!/bin/bash

# generating load:  sudo ./build/app -a $NET_PCI --lcores 0@(2,4) -- --client --ip-local 192.168.1.2 --ip-dest 192.168.1.1 --no-arp


mode=single_queue
cores=( 12 14 16 18 20 )
max_cores=${#cores[@]}

num_cores=1
delay=0
xdp_prog=./xdpsock_kern.o # xdp program to load
qid=0 # queue to attach to
base_port=8080

HAS_BPFTOOL=1

usage() {
	printf "Usage: $0\n"
	printf "  -c --cores: (default: 1) number of cores to use\n"
	printf "  -d --delay: (defalut: 0) packet processing cost\n"
	printf "  -m --multi: (defalut: false) run multi-queue experiment with aRFS\n"
}

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
		-m|--multi)
			mode=multi_queue
			shift;
			;;
		-h|--help)
			usage
			shift
			exit 0
			;;
		*)
			usage
			echo "Unexpected argument ($key)"
			exit 1
			;;
	esac
done

remove_all_rules() {
	sudo ethtool -K $NET_IFACE ntuple-filters on
	old_rules=( $(sudo ethtool -u $NET_IFACE | grep Filter | cut -d ' ' -f 2) )
	for r in ${old_rules[@]}; do
		sudo ethtool -U $NET_IFACE delete $r
	done
}

configure_flow_steering_rules() {
	remove_all_rules
	sudo ethtool -X $NET_IFACE equal $num_cores
	for i in $( seq 0 $((num_cores-1)) ); do
		target=$((base_port + i))
		sudo ethtool -U $NET_IFACE flow-type udp4 dst-port $target action $i
	done
	echo "configure queue to core pinning yourself :) (if needed)"
}

echo "Runing experiment: $mode with $num_cores workers"
case $mode in
	single_queue)
		if [ $HAS_BPFTOOL -eq 1 ]; then
			sudo bpftool net detach xdp dev $NET_IFACE
		fi
		remove_all_rules
		sudo ethtool -X $NET_IFACE equal 1
		arg_cores=""
		for i in $(seq 0 $((num_cores-1)) );do
			arg_cores="$arg_cores -i $NET_IFACE -q $qid -c ${cores[$i]}"
		done
		cmd="sudo ./xsk_fwd -b 131072 -x $xdp_prog $arg_cores -d $delay"
		echo $cmd
		$cmd
		;;
	multi_queue)
		configure_flow_steering_rules
		arg_cores=""
		for i in $(seq 0 $((num_cores-1)) );do
			arg_cores="$arg_cores -i $NET_IFACE -q $i -c ${cores[$i]}"
		done
		cmd="sudo ./xsk_fwd -b 131072 $arg_cores -d $delay"
		echo $cmd
		$cmd
		;;
	*)
		echo Unsuported mode
		exit 1
		;;
esac

echo Done
