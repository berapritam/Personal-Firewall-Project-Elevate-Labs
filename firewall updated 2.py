import subprocess
import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, IP, TCP, UDP  # For optional sniffing
import threading  # For running sniffer in background

# Global list to store rules
rules = []

# Function to apply a rule to iptables
def apply_rule(rule):
    # Build iptables command based on rule
    # Example: iptables -A INPUT -s 192.168.1.1 -p tcp --dport 80 -j DROP
    cmd = ['sudo', 'iptables', '-A', 'INPUT']  # Focus on INPUT chain for incoming IPv4 traffic
    if 'src_ip' in rule and rule['src_ip']:
        cmd.extend(['-s', rule['src_ip']])
    if 'dst_ip' in rule and rule['dst_ip']:
        cmd.extend(['-d', rule['dst_ip']])
    if 'protocol' in rule and rule['protocol']:
        cmd.extend(['-p', rule['protocol']])
    if 'dst_port' in rule and rule['dst_port']:
        cmd.extend(['--dport', str(rule['dst_port'])])
    if 'src_port' in rule and rule['src_port']:
        cmd.extend(['--sport', str(rule['src_port'])])
    cmd.extend(['-j', rule['action'].upper()])  # ACCEPT or DROP
    
    try:
        subprocess.run(cmd, check=True)
        print(f"Applied rule: {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to apply rule: {e}")

# Function to flush all iptables rules (for reset)
def flush_rules():
    subprocess.run(['sudo', 'iptables', '-F', 'INPUT'], check=True)
    rules.clear()
    messagebox.showinfo("Info", "All rules flushed.")

# Optional: Packet sniffer to log traffic (runs in thread)
def packet_sniffer():
    def pkt_callback(pkt):
        if IP in pkt and pkt[IP].version == 4:  # IPv4 only
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = 'tcp' if TCP in pkt else 'udp' if UDP in pkt else 'other'
            sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else None
            dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else None
            print(f"Packet: {src_ip}:{sport} -> {dst_ip}:{dport} ({protocol})")
            # Check against rules (simple match; in real firewall, this would be enforced by iptables)
            for rule in rules:
                if (rule.get('src_ip') == src_ip or not rule.get('src_ip')) and \
                   (rule.get('dst_ip') == dst_ip or not rule.get('dst_ip')) and \
                   (rule.get('protocol') == protocol or not rule.get('protocol')) and \
                   (rule.get('dst_port') == dport or not rule.get('dst_port')):
                    if rule['action'].upper() == 'DROP':
                        print("Packet dropped based on rule.")
                        return  # Simulate drop
            print("Packet allowed.")
    
    sniff(prn=pkt_callback, store=0, filter="ip")  # Sniff IPv4 packets

# GUI Class
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Personal IPv4 Firewall")
        
        # Rule input fields
        tk.Label(root, text="Action (ACCEPT/DROP):").grid(row=0, column=0)
        self.action_entry = tk.Entry(root)
        self.action_entry.grid(row=0, column=1)
        
        tk.Label(root, text="Source IP (e.g., 192.168.1.1):").grid(row=1, column=0)
        self.src_ip_entry = tk.Entry(root)
        self.src_ip_entry.grid(row=1, column=1)
        
        tk.Label(root, text="Destination IP:").grid(row=2, column=0)
        self.dst_ip_entry = tk.Entry(root)
        self.dst_ip_entry.grid(row=2, column=1)
        
        tk.Label(root, text="Protocol (tcp/udp):").grid(row=3, column=0)
        self.protocol_entry = tk.Entry(root)
        self.protocol_entry.grid(row=3, column=1)
        
        tk.Label(root, text="Destination Port:").grid(row=4, column=0)
        self.dst_port_entry = tk.Entry(root)
        self.dst_port_entry.grid(row=4, column=1)
        
        tk.Label(root, text="Source Port:").grid(row=5, column=0)
        self.src_port_entry = tk.Entry(root)
        self.src_port_entry.grid(row=5, column=1)
        
        # Buttons
        tk.Button(root, text="Add Rule", command=self.add_rule).grid(row=6, column=0)
        tk.Button(root, text="Flush Rules", command=flush_rules).grid(row=6, column=1)
        tk.Button(root, text="Start Sniffer", command=self.start_sniffer).grid(row=7, column=0)
        tk.Button(root, text="Stop Sniffer", command=self.stop_sniffer).grid(row=7, column=1)
        
        # Rules list
        self.rules_list = tk.Listbox(root, height=10, width=50)
        self.rules_list.grid(row=8, column=0, columnspan=2)
        
        self.sniffer_thread = None
    
    def add_rule(self):
        rule = {
            'action': self.action_entry.get(),
            'src_ip': self.src_ip_entry.get(),
            'dst_ip': self.dst_ip_entry.get(),
            'protocol': self.protocol_entry.get(),
            'dst_port': int(self.dst_port_entry.get()) if self.dst_port_entry.get() else None,
            'src_port': int(self.src_port_entry.get()) if self.src_port_entry.get() else None,
        }
        rules.append(rule)
        apply_rule(rule)
        self.rules_list.insert(tk.END, str(rule))
        messagebox.showinfo("Info", "Rule added and applied.")
    
    def start_sniffer(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            messagebox.showwarning("Warning", "Sniffer already running.")
            return
        self.sniffer_thread = threading.Thread(target=packet_sniffer)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        messagebox.showinfo("Info", "Sniffer started. Check console for logs.")
    
    def stop_sniffer(self):
        if self.sniffer_thread:
            # Note: Scapy sniff doesn't have a direct stop; this is a simple way
            messagebox.showinfo("Info", "Sniffer stopped (restart script to fully stop).")

# Main execution
if __name__ == "__main__":
    root = tk.Tk()
    gui = FirewallGUI(root)
    root.mainloop()
