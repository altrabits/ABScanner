import os
import json
import psutil
import socket
import ipaddress
import threading
import webbrowser
from enum import Enum
from typing import Dict, Any
from tkinter import ttk, Tk, PhotoImage, messagebox, scrolledtext, Frame, Menu, IntVar, END

BROADCAST_IP = "255.255.255.255"
PORT = 30303


class MCHPDiscoverMessage:
    def __init__(self, addr: Any, data: bytes):
        self.addr = addr
        self.macAddr = None
        self.macType = None
        self.hostName = None
        self.IPv4Addr = None
        self.user = None

        idx = 0
        while idx < len(data):
            c = data[idx]
            idx += 1  # Skip current

            if c == 0x01:
                pass

            elif c == 0x02:  # MAC Address
                self.macAddr = ":".join(f"{b:02X}" for b in data[idx:idx + 6])
                idx += 6
                if data[idx] != 0x0d or data[idx + 1] != 0x0a:
                    print("Invalid MAC Address")
                    break
                idx += 2

            elif c == 0x03:  # MAC Type
                temp = []
                while idx < len(data):
                    if data[idx] == 0x0d and data[idx + 1] == 0x0a:
                        break
                    temp.append(chr(data[idx]))
                    idx += 1
                self.macType = "".join(temp).strip()

                if data[idx] != 0x0d or data[idx + 1] != 0x0a:
                    print("Invalid MAC Type")
                    break
                idx += 2

            elif c == 0x04:  # Host name
                temp = []
                while idx < len(data):
                    if data[idx] == 0x0d and data[idx + 1] == 0x0a:
                        break
                    temp.append(chr(data[idx]))
                    idx += 1
                self.hostName = "".join(temp).strip()

                if data[idx] != 0x0d or data[idx + 1] != 0x0a:
                    print("Invalid Host name")
                    break
                idx += 2

            elif c == 0x05:  # IPv4 Address
                self.IPv4Addr = ".".join(f"{b}" for b in data[idx:idx + 4])
                idx += 4

                if data[idx] != 0x0d or data[idx + 1] != 0x0a:
                    print("Invalid IPv4 Address")
                    break
                idx += 2

            elif c == 0x06 or c == 0x07 or c == 0x08 or c == 0x09:
                # Not implemented yet, discard bytes until \r\n
                while data[idx] != 0x0d and data[idx + 1] != 0x0a:
                    idx += 1
                idx += 2

            elif c == 0x0a:  # User data
                self.user = data[idx:].decode("utf-8")
                break  # done

    def get_user_json(self) -> Dict[str, Any]:
        try:
            return json.loads(self.user)
        except json.decoder.JSONDecodeError:
            return {}


class Broadcast(Enum):
    DIRECT = 1
    LIMITED = 2


class Scanner:
    def __init__(self, title: str, icon_path: str):
        self.on_close_ext = None

        self.sock = None

        self.root = Tk()
        self.root.title(title)

        if os.path.isfile(icon_path):
            logo = PhotoImage(file=icon_path)
            self.root.iconphoto(True, logo)
        else:
            # Load using PyInstaller
            icon_path = self.resource_path(icon_path)
            logo = PhotoImage(file=icon_path)
            self.root.iconphoto(True, logo)

        window_width = 600
        window_height = 500

        # Get the screen dimension
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Find the center point
        center_x = int(screen_width / 2 - window_width / 2)
        center_y = int(screen_height / 2 - window_height / 2)

        # Set the position of the window to the center of the screen
        self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        # self.root.geometry("600x800")

        # create a menubar
        menubar = Menu(self.root)

        # File
        file_menu = Menu(menubar, tearoff=0)
        # file_menu.add_command(label='New')

        self.broadcast_option = IntVar(value=Broadcast.LIMITED.value)
        network_menu = Menu(menubar, tearoff=0)
        network_menu.add_radiobutton(label="Direct (Eg. xxx.yyy.zzz.255)", variable=self.broadcast_option, value=Broadcast.DIRECT.value)
        network_menu.add_radiobutton(label="Limited (Eg. 255.255.255.255)", variable=self.broadcast_option, value=Broadcast.LIMITED.value)
        file_menu.add_cascade(label="Broadcast", menu=network_menu)

        file_menu.add_separator()
        file_menu.add_command(label='Exit', command=self.on_close)

        # Add the File menu to the menubar
        menubar.add_cascade(label="File", menu=file_menu)

        # create the Help menu
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label='About...', command=lambda: messagebox.showinfo("AltraBits", f"AB Scanner v1.0"))
        # add the Help menu to the menubar
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.config(menu=menubar)

        self.frame = Frame(self.root)
        self.frame.pack(pady=10)

        # Scan button, send UDP broadcast discovery packet
        self.scan_button = ttk.Button(self.frame, text="Scan", command=self.scan_now)
        self.scan_button.pack(pady=5)

        # Text area for incoming messages
        self.text_area = scrolledtext.ScrolledText(self.frame, state="disabled")
        self.text_area.pack(padx=10, pady=10, expand=True)

        # Get local IPs to avoid processing own broadcasts
        self.local_ips = self.get_active_ipv4_broadcasts()

        # Create UDP listener thread
        self.devices = set()
        self.stop_event = threading.Event()
        self.listener_thread = threading.Thread(target=self.listen_udp, daemon=True)

    @staticmethod
    def resource_path(relative_path):
        """ Get absolute path to resource, works for dev and for PyInstaller """
        if hasattr(sys, "_MEIPASS"):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

    def draw_window(self):
        self.root.mainloop()

    def on_close(self):
        print("Closing...")
        self.stop_event.set()
        self.sock.close()  # Force exiting from blocking recv
        self.listener_thread.join()
        self.root.destroy()

    def open_socket(self) -> None:
        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Allow reusing the port (important if you also receive on it)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        try:
            # Bind to local port 30303
            self.sock.bind(("", PORT))
        except PermissionError as e:
            messagebox.showerror("Cannot open datagram socket", message=f"The local port {PORT} may be already in use.")
            print(e)
            exit(1)
        except Exception as e:
            messagebox.showerror("Application Error", f"An unexpected error occurred:\n{e}")
            exit(1)

        self.listener_thread.start()

    @staticmethod
    def get_active_ipv4_broadcasts():
        result = []

        for iface_name, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(iface_name)
            if not stats or not stats.isup:
                continue  # skip inactive interfaces

            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4 only
                    ip = addr.address
                    netmask = addr.netmask

                    if not ip or ip.startswith("127."):
                        continue  # skip loopback

                    # Determine broadcast address
                    if addr.broadcast:
                        broadcast = addr.broadcast
                    elif netmask:
                        # Calculate broadcast manually
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        broadcast = str(network.broadcast_address)
                    else:
                        # fallback if netmask not available
                        broadcast = ip  # just use IP as broadcast (rare)

                    result.append((iface_name, ip, broadcast))

        return result

    def scan_now(self):
        print("Scanning...")
        self.disable_scan_button(True)
        self.clear_results()
        self.devices = set()

        message = "Discovery: Who is out there?\0\n".encode("utf-8")

        if self.broadcast_option.get() == Broadcast.DIRECT.value:
            # Direct broadcast Eg xxx.yyy.zzz.255
            for local_ip in {ip[2] for ip in self.local_ips}:
                self.sock.sendto(message, (local_ip, PORT))
        else:
            # Limited broadcast 255.255.255.255
            self.sock.sendto(message, (BROADCAST_IP, PORT))

        self.frame.after(700, self.disable_scan_button, False)

    def disable_scan_button(self, disabled: bool):
        if disabled:
            self.scan_button.config(text="Scanning...", state="disabled")
        else:
            self.scan_button.config(text="Scan", state="!disabled")

    def clear_results(self):
        self.text_area.config(state="normal")
        self.text_area.delete('1.0', END)
        self.text_area.config(state="disabled")

    def add_device(self, device: MCHPDiscoverMessage):
        if device.macAddr in self.devices:
            # Do not add the same device multiple times
            return

        self.devices.add(device.macAddr)
        user = device.get_user_json()

        msg1 = f"{len(self.devices)}. {user["PN"]} "
        msg2 = f"http://{device.addr[0]}/"
        msg3 = "\n"
        msg = msg1 + msg2 + msg3

        # Append message and set links
        self.text_area.config(state="normal")
        self.text_area.insert(END, msg)

        # Add link
        row = len(self.devices)
        col_start = len(msg1)
        col_stop = len(msg1) + len(msg2)
        self.text_area.tag_add("link", f"{row}.{col_start}", f"{row}.{col_stop}")
        self.text_area.tag_config("link", foreground="blue", underline=True)
        # Link click
        self.text_area.tag_bind("link", "<Button-1>", lambda e: webbrowser.open(msg2))
        # :ink hover
        self.text_area.tag_bind("link", "<Enter>", lambda e: self.text_area.config(cursor="hand2"))
        # :ink leave
        self.text_area.tag_bind("link", "<Leave>", lambda e: self.text_area.config(cursor=""))

        self.text_area.see(END)
        self.text_area.config(state="disabled")

    def listen_udp(self):
        while not self.stop_event.is_set():
            local_ips = [ip[1] for ip in self.local_ips]
            try:
                data, addr = self.sock.recvfrom(1500 - 28)
                # Skip if message is from self
                if addr[0] in local_ips:
                    continue

                self.frame.after(0, self.add_device, MCHPDiscoverMessage(addr, data))
            except OSError as e:
                # Happens if socket is closed from outside
                print("Socket closed:", e)
            except Exception as e:
                print(e)
                messagebox.showerror("Application Error", f"An unexpected error occurred:\n{e}")
                exit(1)


if __name__ == '__main__':
    print('Running...\n')

    scanner = Scanner("AltraBits Scanner", "ab_cobalt.png")
    scanner.open_socket()
    scanner.draw_window()

    print('Done.\n')
