import psutil
import ctypes
import tkinter as tk
from scapy.all import sniff
from tkinter import messagebox


def show_message(message):
    ctypes.windll.user32.MessageBoxW(0, message, "PLC Vendor Detection", 1)

def detect_plc_vendor(packet_data):
    data = packet_data.decode(errors='ignore')
    if "Siemens" in data:
        return "Siemens"
    if "Schneider" in data:
        return "Schneider Electric"
    if "Rockwell" in data:
        return "Rockwell Automation"
    return "Unknown Vendor"

def capture_packets_and_detect_vendor(interface):
    try:
        packets = sniff(iface=interface, timeout=10)
        for packet in packets:
            vendor = detect_plc_vendor(str(packet))
            if vendor != "Unknown Vendor":
                show_message(f"Detected PLC Vendor: {vendor}")
                return
        show_message("No PLC Vendor detected.")
    except Exception as e:
        show_message(f"Error: {str(e)}")

def on_start_button_click():
    interface = interface_var.get()
    if not interface:
        show_message("Please select an interface.")
        return
    show_message("Detecting manufacturer name......")
    capture_packets_and_detect_vendor(interface)

def update_interface_list():
    interfaces = psutil.net_if_addrs().keys()
    interface_menu['menu'].delete(0, 'end')
    for iface in interfaces:
        interface_menu['menu'].add_command(
            label=iface, command=tk._setit(interface_var, iface))

root = tk.Tk()
root.title("PLC Vendor Detection")

interface_var = tk.StringVar(root)
interface_var.set("Select Interface")
interface_label = tk.Label(root, text="Select Network Interface:")
interface_label.pack(pady=10)
interface_menu = tk.OptionMenu(root, interface_var, [])
interface_menu.pack(pady=10)

update_interface_list_button = tk.Button(
    root, text="Update Interface List", command=update_interface_list)
update_interface_list_button.pack(pady=10)

start_button = tk.Button(root, text="Start Detection",
                         command=on_start_button_click)
start_button.pack(pady=10)
root.mainloop()
