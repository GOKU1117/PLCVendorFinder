import json
import psutil
import ctypes
import tkinter as tk
import tkinter.ttk as ttk
from PIL import Image
from PIL import ImageTk
from scapy.all import sniff
from scapy.all import Ether
from tkinter import messagebox


def load_vendor_data():
    with open('PLCOui.json', 'r') as f:
        return json.load(f)

def show_message(message):
    ctypes.windll.user32.MessageBoxW(0, message, "PLC Vendor Detection", 1)

def detect_plc_vendor(mac_address, vendor_data):
    mac_prefix = mac_address.upper()[:8]
    return vendor_data.get(mac_prefix, "Unknown Vendor")

def capture_packets_and_detect_vendor(interface, vendor_data):
    try:
        packets = sniff(iface=interface, timeout=10)
        for packet in packets:
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                vendor_src = detect_plc_vendor(src_mac, vendor_data)
                vendor_dst = detect_plc_vendor(dst_mac, vendor_data)
                if vendor_src != "Unknown Vendor" or vendor_dst != "Unknown Vendor":
                    show_message(
                        f"Detected PLC Vendor: {vendor_src if vendor_src != 'Unknown Vendor' else vendor_dst}")
                    return
        show_message("No PLC Vendor detected.")
    except Exception as e:
        show_message(f"Error: {str(e)}")

def on_start_button_click():
    if messagebox.askyesno("Confirmation", "Do you want to start detection?"):
        show_message("Detecting manufacturer name... Please do not close this window.")
        interface = interface_var.get()
        if not interface:
            show_message("Please select an interface.")
            return
        vendor_data = load_vendor_data()
        capture_packets_and_detect_vendor(interface, vendor_data)

def update_interface_list():
    interfaces = psutil.net_if_addrs().keys()
    interface_menu['menu'].delete(0, 'end')
    for iface in interfaces:
        interface_menu['menu'].add_command(
            label=iface, command=tk._setit(interface_var, iface))

root = tk.Tk()
root.title("PLC Vendor Detection")
root.geometry("400x300")
root.configure(bg="#f0f0f0")

interface_var = tk.StringVar(root)
interface_var.set("Select Interface")

style = ttk.Style()
style.configure('TLabel', font=('Arial', 12), background='#f0f0f0')
style.configure('TButton', font=('Arial', 10))

interface_label = ttk.Label(root, text="Select Network Interface:")
interface_label.pack(pady=10)

interface_menu = ttk.OptionMenu(root, interface_var, [])
interface_menu.pack(pady=10)

update_interface_list_button = ttk.Button(
    root, text="Update Interface List", command=update_interface_list)
update_interface_list_button.pack(pady=10)

start_button = ttk.Button(root, text="Start Detection",
                          command=on_start_button_click)
start_button.pack(pady=10)

update_interface_list()
root.mainloop()
