## CRASH TEST ##

filterstrs = [
        "tcp src port 92",
        "len <= 1000",
        "ether proto 0x800",
        "ip proto 47 or ip6 proto 47",
        "ip host 22.22.22.22"
        ]

filter0 = {"priority" : 0, "filter" : filterstrs[0], "gate" : 1}
bpf0::BPF()
bpf0.add(filters=[filter0])
CRASH_TEST_INPUTS.append([bpf0, 1, 2])

bpf1::BPF()
for i in range(len(filterstrs)):
    bpf1.add(filters=[{"priority": i, "filter": filterstrs[i], "gate": i}])

CRASH_TEST_INPUTS.append([bpf1, 1, len(filterstrs)])

## OUTPUT TEST ##

# Test basic output/steering with single rule
bpf2::BPF()
bpf2.add(filters=[filter0])
packet1 = str(gen_packet(scapy.UDP, '12.34.56.78', '12.34.56.78'))
packet2 = str(gen_packet(scapy.TCP, '12.34.56.78', '12.34.56.78', srcport=92))

OUTPUT_TEST_INPUTS.append([bpf2,
    1,2,
    [{'input_port' : 0,
        'input_packet' : packet1,
        'output_port' : 0,
        'output_packet' : packet1},
     {'input_port' : 0,
         'input_packet' : packet2,
         'output_port': 1,
         'output_packet': packet2}]])

# Test multiple rules with priorities
bpf3::BPF()
bpf3.add(filters=[{"priority":2, "filter": filterstrs[0],"gate": 1}])
bpf3.add(filters=[{"priority":1, "filter": filterstrs[4],"gate": 2}])
packet1 = str(gen_packet(scapy.UDP, '22.22.22.22', '12.34.56.78', srcport=700))
packet2 = str(gen_packet(scapy.TCP, '12.34.56.78', '22.22.22.22', srcport=92))
packet3 = str(gen_packet(scapy.TCP, '12.34.56.78', '12.34.56.78', srcport=700))

OUTPUT_TEST_INPUTS.append([bpf3,
    1,3,
    [{'input_port': 0,
        'input_packet': packet1,
        'output_port': 2,
        'output_packet': packet1},
    {'input_port': 0,
        'input_packet': packet2,
        'output_port': 1,
        'output_packet': packet2},
    {'input_port': 0,
        'input_packet': packet3,
        'output_port': 0,
        'output_packet': packet3}]])
