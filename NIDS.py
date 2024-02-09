import tkinter as tk
from tkinter import messagebox, filedialog
import threading
from scapy.all import sniff, wrpcap, IP, TCP, send, UDP, DNS, DNSQR
import datetime
import winsound
import pickle
import time
from PIL import Image, ImageTk
class NIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Intrusion Detection System")

        logo_img = Image.open("school_logo.png")
        logo_img = logo_img.resize((100, 100), Image.LANCZOS)
        self.school_logo = ImageTk.PhotoImage(logo_img)

        self.logo_label = tk.Label(self.root, image=self.school_logo)
        self.logo_label.grid(row=0, column=0, padx=10, pady=10)

        self.packet_info_label = tk.Label(self.root, text="Packet Information")
        self.packet_info_label.grid(row=1, column=0, padx=10, pady=10)  

        self.packet_info_text = tk.Text(self.root, height=20, width=80, font=("Helvetica", 10))
        self.packet_info_text.grid(row=2, column=0, padx=10, pady=5)  

        self.alert_log_label = tk.Label(self.root, text="Alert Log")
        self.alert_log_label.grid(row=3, column=0, padx=10, pady=10)  

        # Change font for alert log text widget
        self.alert_log_text = tk.Text(self.root, height=10, width=100, font=("Helvetica", 10))
        self.alert_log_text.grid(row=4, column=0, padx=10, pady=5)  

        self.start_button = tk.Button(self.root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=5, column=0, padx=10, pady=5)

        self.stop_button = tk.Button(self.root, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=6, column=0, padx=10, pady=5)

        self.save_packets_button = tk.Button(self.root, text="Save Packets", command=self.save_packets, state=tk.DISABLED)
        self.save_packets_button.grid(row=7, column=0, padx=10, pady=5)

        self.save_alerts_button = tk.Button(self.root, text="Save Alerts", command=self.save_alerts, state=tk.DISABLED)
        self.save_alerts_button.grid(row=8, column=0, padx=10, pady=5)

        self.clear_alerts_button = tk.Button(self.root, text="Clear Alerts", command=self.clear_alerts, state=tk.DISABLED)
        self.clear_alerts_button.grid(row=9, column=0, padx=10, pady=5)

        self.interface = 'Wi-Fi'
        self.stop_event = threading.Event()

        self.rules_file = 'rules.txt'
        self.malicious_ips = self.load_malicious_ips(self.rules_file)

        self.alerts = []
        self.alert_count = 0
        self.alert_label = tk.Label(self.root, text="Alerts: 0")
        self.alert_label.grid(row=10, column=0, padx=10, pady=5)

        self.packet_count = 0
        self.packets = []

        self.load_saved_data()

    def send_fake_packet(self):
        fake_tcp_packet = IP(src="192.168.1.100", dst="8.8.8.8") / TCP(dport=80)
        fake_dns_packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="www.meanhackers.com"))

        time.sleep(5)

        send(fake_dns_packet)

        time.sleep(5)

        send(fake_tcp_packet)


    def load_malicious_ips(self, rules_file):
        malicious_ips = []

        with open(rules_file, 'r') as file:
            for line in file:
                parts = line.strip().split(', ')
                if len(parts) == 3 and parts[0] == 'IP' and parts[2] == 'Malicious IP detected':
                    malicious_ips.append(parts[1])

        return malicious_ips

    def load_saved_data(self):
        try:
            with open('nids_data.pkl', 'rb') as file:
                saved_data = pickle.load(file)
                self.alerts = saved_data.get('alerts', [])
                self.packets = saved_data.get('packets', [])
                self.alert_count = len(self.alerts)
                self.update_alert_log()
        except FileNotFoundError:
            pass

    def save_data(self):
        data = {'alerts': self.alerts, 'packets': self.packets}

        with open('nids_data.pkl', 'wb') as file:
            pickle.dump(data, file)

    def capture_and_analyze_packets(self):
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.start()

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=0, filter='tcp or udp or (icmp and (ip or ip6))', iface=self.interface, stop_filter=self.stop_sniffing)

    def stop_sniffing(self, packet):
        return self.stop_event.is_set()

    def process_packet(self, packet):
        self.packet_count += 1
        self.packets.append(packet)

        source_ip = ""
        protocol = ""
        source_port = ""
        destination_port = ""
        payload = ""
        domain_name = ""

        if IP in packet:
            source_ip = packet[IP].src
        else:
            return

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            payload = str(packet[TCP].payload)
        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            payload = str(packet[UDP].payload)

        if DNS in packet and packet[DNS].qdcount > 0:
            domain_name = packet[DNS].qd.qname.decode('utf-8')

            if domain_name and self.is_malicious_domain(domain_name):
                self.handle_alert(source_ip, f"Malicious domain detected: {domain_name}")

        packet_info = {
            "source_ip": source_ip,
            "destination_ip": packet[IP].dst,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "payload": payload,
            "packet_size": len(packet),
            "domain_name": domain_name
        }

        self.update_gui(packet_info)
        self.update_alert_label()

        if source_ip in self.malicious_ips:
            self.handle_alert(source_ip, "Malicious IP detected")


    def check_dns_packet(self, packet):
        if 'DNS' in packet:
            dns_packet = packet['DNS']
            if dns_packet.qdcount > 0:
                domain_name = dns_packet.qd.qname.decode('utf-8')
                if self.is_malicious_domain(domain_name):
                    source_ip = packet['IP'].src
                    self.handle_alert(source_ip, f"Malicious domain detected: {domain_name}")
                    return domain_name

    def handle_alert(self, source_ip, description):
        self.alert_count += 1
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.alerts.append((timestamp, source_ip, description))
        self.update_alert_log()
        self.play_alert_sound()

    def is_malicious_domain(self, domain_name):
        with open(self.rules_file, 'r') as file:
            for line in file:
                parts = line.strip().split(', ')
                if len(parts) == 3 and parts[0] == 'Domain' and parts[1] == domain_name and parts[2] == 'Malicious domain detected':
                    return True
        return False

    def update_gui(self, packet_info):
        packet_str = f"Source IP: {packet_info['source_ip']}\n" \
                    f"Destination IP: {packet_info['destination_ip']}\n" \
                    f"Source Port: {packet_info['source_port']}\n" \
                    f"Destination Port: {packet_info['destination_port']}\n" \
                    f"Protocol: {packet_info['protocol']}\n" \
                    f"Packet Size: {packet_info['packet_size']} bytes\n"

        if 'domain_name' in packet_info:
            packet_str += f"Domain Name: {packet_info['domain_name']}\n"

        if packet_info['payload']:
            packet_str += f"Payload: {packet_info['payload']}\n"

        packet_str += "\n"

        self.packet_info_text.insert(tk.END, packet_str)
        self.packet_info_text.see(tk.END)

    def update_alert_label(self):
        self.alert_label.config(text=f"Alerts: {self.alert_count}")

    def update_alert_log(self):
        self.alert_log_text.delete('1.0', tk.END)
        for i, (timestamp, ip, description) in enumerate(self.alerts, start=1):
            self.alert_log_text.insert(tk.END, f"#{i}: {timestamp} - {ip} - {description}\n")

    def start_monitoring(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_packets_button.config(state=tk.NORMAL)
        self.save_alerts_button.config(state=tk.NORMAL)
        self.clear_alerts_button.config(state=tk.NORMAL)

        self.stop_event.clear()

        threading.Thread(target=self.capture_and_analyze_packets).start()

        threading.Thread(target=self.send_fake_packet).start()

    def stop_monitoring(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_packets_button.config(state=tk.NORMAL)
        self.save_alerts_button.config(state=tk.NORMAL)
        self.stop_event.set()

        self.save_data()

    def save_packets(self):
        if not self.packets:
            messagebox.showerror("Error", "No packets to save.")
            return

        self.save_data()

        filename = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if filename:
            packets_with_domain = []
            for packet in self.packets:
                packet_with_domain = packet.copy()
                if 'DNS' in packet_with_domain and packet_with_domain['DNS'].qdcount > 0:
                    domain_name = packet_with_domain['DNS'].qd.qname.decode('utf-8')
                    packet_with_domain['DNS'].qd.qname = domain_name
                packets_with_domain.append(packet_with_domain)

            wrpcap(filename, packets_with_domain)
            messagebox.showinfo("Packets Saved", f"Packets saved to {filename}")

    def save_alerts(self):
        if not self.alerts:
            messagebox.showerror("Error", "No alerts to save.")
            return

        self.save_data()

        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filename:
            with open(filename, 'w') as file:
                for timestamp, ip, description in self.alerts:
                    file.write(f"{timestamp} - Malicious IP {ip} - {description}\n")
            messagebox.showinfo("Alerts Saved", f"Alerts saved to {filename}")

    def clear_alerts(self):
        self.alerts = []
        self.alert_count = 0
        self.update_alert_log()
        self.update_alert_label()

        self.clear_alert_log_file()

    def clear_alert_log_file(self):
        try:
            open('alert_log.txt', 'w').close()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear alert log file: {e}")

    def play_alert_sound(self):
        winsound.PlaySound("alert.wav", winsound.SND_FILENAME)

if __name__ == "__main__":
    root = tk.Tk()
    app = NIDSApp(root)

    root.geometry("1920x1080")
    
    root.mainloop()
