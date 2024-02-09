import pyshark
import json

def capture_and_save_packets(interface, packet_count, output_file):
    captured_packets = []

    capture = pyshark.LiveCapture(interface=interface, display_filter='tcp')

    for packet in capture.sniff_continuously(packet_count=packet_count):
        # Check if 'ip' attribute is present in the packet
        if hasattr(packet, 'ip'):
            # Extract relevant packet information
            packet_info = {
                "source_ip": getattr(packet.ip, 'src', None),
                "destination_ip": getattr(packet.ip, 'dst', None),
                "source_port": getattr(packet[packet.transport_layer], 'srcport', None),
                "destination_port": getattr(packet[packet.transport_layer], 'dstport', None),
                "protocol": getattr(packet, 'transport_layer', None),
            }

            # Include payload analysis
            if 'data' in packet:
                # Check if payload is available
                packet_info["payload"] = str(packet.data)
            elif 'http' in packet and hasattr(packet.http, 'data'):
                # Check for HTTP packets
                packet_info["payload"] = str(packet.http.data)
            elif 'tcp' in packet and hasattr(packet.tcp, 'payload'):
                # Check for TCP packets
                packet_info["payload"] = str(packet.tcp.payload)
            else:
                # If payload is not present, fill with None
                packet_info["payload"] = None

            # Include packet size
            packet_info["packet_size"] = len(packet)

            # Append the packet information to the list
            captured_packets.append(packet_info)

    # Save captured packets to a JSON file if there are packets
    if captured_packets:
        with open(output_file, 'w') as json_file:
            json.dump(captured_packets, json_file, indent=2)

# Example usage
capture_and_save_packets('Wi-Fi', 5, 'captured_packets.json')
