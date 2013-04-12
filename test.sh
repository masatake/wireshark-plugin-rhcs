mkdir -p pdml.$$

for p in pcap/*.pcap; do
    if ! [[ $p == "dont-*" ]] ;then
	echo -n checking ${p/pcap\//}...
	pdml=$(basename $p .pcap).pdml
	tshark -o corosync_totemnet.private_keys:"beta;alpha:example.com" -t e -r $p -T pdml > pdml.$$/$pdml 2> /dev/null
	if diff -uN <(grep -v pdml pdml/$pdml) <(grep -v pdml pdml.$$/$pdml) > /dev/null; then
	    echo successful
	else
	    echo failed "(see pdml.$$/$pdml)"
	fi
    fi
done
