import json

def load_rules(rules_file):

    with open(rules_file, 'r') as file:
        rules = [line.strip().split(', ') for line in file]

    return rules

def analyze_packets(json_file, rules_file):
    with open(json_file, 'r') as file:
        captured_packets = json.load(file)

    rules = load_rules(rules_file)

    malicious_ips = [rule[1] for rule in rules if rule[0] == 'IP' and len(rule) == 3 and rule[2] == 'Malicious IP detected']

    for idx, packet in enumerate(captured_packets, 1):
        print(f"\nPacket {idx} Analysis:")
        print(f"Source IP: {packet['source_ip']}")
        print(f"Destination IP: {packet['destination_ip']}")
        print(f"Source Port: {packet['source_port']}")
        print(f"Destination Port: {packet['destination_port']}")
        print(f"Protocol: {packet['protocol']}")
        print(f"Payload: {packet['payload']}")
        print(f"Packet Size: {packet['packet_size']} bytes")

        if packet['source_ip'] in malicious_ips:
            print("Malicious IP Detected!")

analyze_packets('captured_packets.json', 'rules.txt')
