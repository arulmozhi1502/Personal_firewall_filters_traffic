import tkinter as tk
import threading
from firewall import start_firewall, stop_firewall

firewall_thread = None

def run_sniffer():
    global firewall_thread
    firewall_thread = threading.Thread(target=start_firewall)
    firewall_thread.start()

def stop_sniffer():
    stop_firewall()
    print("Firewall stopped.")

root = tk.Tk()
root.title("Personal Firewall")

label = tk.Label(root, text="Firewall Control", font=("Arial", 14))
label.pack(pady=20)

start_btn = tk.Button(root, text="Start Firewall", command=run_sniffer)
start_btn.pack(pady=10)

stop_btn = tk.Button(root, text="Stop Firewall", command=stop_sniffer)
stop_btn.pack(pady=10)

root.mainloop()
