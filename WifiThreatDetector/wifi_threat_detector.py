import pywifi
from pywifi import const
import time
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import matplotlib.pyplot as plt
import csv
import platform
import subprocess  # For external commands
import sqlite3      # For database logging
from datetime import datetime

# For embedding matplotlib in Tkinter
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.figure as mplfig

# Tooltip class for generic widget hover explanations
class CreateToolTip(object):
    def __init__(self, widget, text='info'):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)

    def enter(self, event=None):
        self.showtip()

    def leave(self, event=None):
        self.hidetip()

    def showtip(self):
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify='left',
                         background="#333", foreground="white",
                         relief='solid', borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tipwindow
        if tw:
            tw.destroy()
        self.tipwindow = None


class WiFiThreatDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Threat Detector")
        self.root.geometry("950x650")
        # Light mode is default.
        self.is_dark_mode = False  
        self.network_data = []
        # For tooltip in the Treeview.
        self.tooltip = None
        # Setup the SQLite database for logging.
        self.setup_database()
        self.setup_gui()
        self.auto_scan()

    def setup_database(self):
        # Connect to (or create) the SQLite database.
        self.conn = sqlite3.connect("wifi_scans.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT,
                network_name TEXT,
                mac_address TEXT,
                signal REAL,
                security TEXT,
                score INTEGER,
                threat TEXT
            );
        """)
        self.conn.commit()

    def log_scan_results(self, scan_time, table_data):
        for row in table_data:
            self.cursor.execute(
                "INSERT INTO scans (scan_time, network_name, mac_address, signal, security, score, threat) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_time, row[0], row[1], row[2], row[3], row[4], row[5])
            )
        self.conn.commit()

    def setup_gui(self):
        style = ttk.Style()

        top_frame = ttk.Frame(self.root)
        top_frame.pack(pady=10)

        self.scan_btn = ttk.Button(top_frame, text="Scan Networks", command=self.manual_scan)
        self.scan_btn.grid(row=0, column=0, padx=5)

        self.graph_btn = ttk.Button(top_frame, text="Show Signal Chart", command=self.show_graph)
        self.graph_btn.grid(row=0, column=1, padx=5)

        self.export_btn = ttk.Button(top_frame, text="Export CSV", command=self.export_csv)
        self.export_btn.grid(row=0, column=2, padx=5)

        self.theme_btn = ttk.Button(top_frame, text="Switch to Dark Mode", command=self.toggle_theme)
        self.theme_btn.grid(row=0, column=3, padx=5)

        # New button for Historical Trends.
        self.trend_btn = ttk.Button(top_frame, text="Historical Trends", command=self.show_trends)
        self.trend_btn.grid(row=0, column=4, padx=5)

        self.status_lbl = ttk.Label(self.root, text="Status: Waiting for scan...")
        self.status_lbl.pack(pady=5)

        # New filter frame for interactive filtering.
        filter_frame = ttk.Frame(self.root)
        filter_frame.pack(pady=5)
        tk.Label(filter_frame, text="Filter by SSID:").pack(side=tk.LEFT, padx=5)
        self.filter_entry = ttk.Entry(filter_frame)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply Filter", command=self.filter_treeview).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_filter).pack(side=tk.LEFT, padx=5)

        # Define Treeview columns and header mapping.
        self.columns = ("ssid", "bssid", "signal", "security", "score", "flag")
        header_texts = {
            "ssid": "Network Name (SSID)",
            "bssid": "MAC Address (BSSID)",
            "signal": "Signal",
            "security": "Security",
            "score": "Penetration test score",
            "flag": "Threat"
        }
        self.tree = ttk.Treeview(self.root, columns=self.columns, show='headings')
        for col in self.columns:
            self.tree.heading(col, text=header_texts.get(col, col.upper()), anchor="center")
            self.tree.column(col, width=150, anchor="center")
        self.tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Bind double-click on a row to show interactive details.
        self.tree.bind("<Double-1>", self.show_network_details)
        self.tree.bind("<Motion>", self.on_treeview_motion)
        self.tree.bind("<Leave>", lambda event: self.hide_tooltip())

        self.recommend_box = tk.Text(self.root, height=8, bg="white", fg="black")
        self.recommend_box.pack(fill=tk.X, padx=10, pady=5)
        self.recommend_box.insert(tk.END, "Recommendations will appear here after scanning...")
        self.recommend_box.config(state=tk.DISABLED)

        self.toggle_dark_mode(style)

    def toggle_theme(self):
        style = ttk.Style()
        self.is_dark_mode = not self.is_dark_mode
        self.toggle_dark_mode(style)
        if self.is_dark_mode:
            self.theme_btn.config(text="Switch to Light Mode")
        else:
            self.theme_btn.config(text="Switch to Dark Mode")

    def toggle_dark_mode(self, style):
        if self.is_dark_mode:
            self.root.configure(bg="#1e1e1e")
            style.theme_use("clam")
            style.configure("Treeview", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e")
            style.configure("TButton", background="#3e3e3e", foreground="white")
            style.configure("TLabel", background="#1e1e1e", foreground="white")
            self.recommend_box.config(bg="#1e1e1e", fg="white")
        else:
            self.root.configure(bg="white")
            style.theme_use("default")
            style.configure("Treeview", background="white", foreground="black", fieldbackground="white")
            style.configure("TButton", background="lightgray", foreground="black")
            style.configure("TLabel", background="white", foreground="black")
            self.recommend_box.config(bg="white", fg="black")

    def filter_treeview(self):
        filter_text = self.filter_entry.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        for row in self.network_data:
            if filter_text in row[0].lower():
                tag = ""
                if row[5] in ["EVIL TWIN", "THREAT"]:
                    tag = "danger"
                elif row[5] == "SUSPECT":
                    tag = "warning"
                self.tree.insert("", tk.END, values=row, tags=(tag,))

    def clear_filter(self):
        self.filter_entry.delete(0, tk.END)
        self.filter_treeview()

    def show_network_details(self, event):
        item = self.tree.focus()
        if not item:
            return
        values = self.tree.item(item, "values")
        if not values:
            return
        ssid = values[0]
        bssid = values[1]
        self.cursor.execute("SELECT scan_time, signal FROM scans WHERE mac_address=? ORDER BY scan_time ASC", (bssid,))
        records = self.cursor.fetchall()
        if not records:
            messagebox.showinfo("No Historical Data", "No historical data available for this network.")
            return
        times = [datetime.fromisoformat(r[0]) for r in records]
        signals = [r[1] for r in records]

        details_window = tk.Toplevel(self.root)
        details_window.title(f"Network Details: {ssid}")
        details_window.geometry("600x500")
        details_text = tk.Text(details_window, height=4, wrap="word")
        details_text.pack(fill=tk.X, padx=10, pady=5)
        details_text.insert(tk.END, f"Network: {ssid}\nMAC Address: {bssid}\nDisplaying historical signal strength trends.\n")
        details_text.config(state=tk.DISABLED)
        fig = mplfig.Figure(figsize=(5,3), dpi=100)
        ax = fig.add_subplot(111)
        ax.plot(times, signals, marker='o')
        ax.set_title("Historical Signal Strength")
        ax.set_xlabel("Time")
        ax.set_ylabel("Signal (dBm)")
        ax.grid(True)
        canvas = FigureCanvasTkAgg(fig, master=details_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def manual_scan(self):
        self.status_lbl.config(text="Scanning networks...")
        threading.Thread(target=self.scan_networks).start()

    def auto_scan(self):
        self.scan_networks()
        # Updated auto scan timer: 120 seconds (120,000 ms) instead of 30 seconds.
        self.root.after(120000, self.auto_scan)

    def scan_networks(self):
        scan_time = datetime.now().isoformat()
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(3)
        results = iface.scan_results()
        ssid_dict = {}
        table_data = []
        for network in results:
            ssid = network.ssid
            bssid = network.bssid
            signal = network.signal
            auth = network.akm[0] if network.akm else None
            security = self.get_security_type(auth)
            score = self.get_score(security, signal)
            flag = ""
            if ssid in ssid_dict:
                ssid_dict[ssid].append(bssid)
            else:
                ssid_dict[ssid] = [bssid]
            if security in ["OPEN", "WEP"]:
                flag = "THREAT"
            elif signal < -85:
                flag = "SUSPECT"
            table_data.append((ssid, bssid, signal, security, score, flag))
        for i in range(len(table_data)):
            ssid = table_data[i][0]
            if len(ssid_dict[ssid]) > 1:
                table_data[i] = (*table_data[i][:5], "EVIL TWIN")
        self.network_data = table_data
        self.log_scan_results(scan_time, table_data)
        self.root.after(0, self.update_ui_after_scan)

    def update_ui_after_scan(self):
        self.tree.delete(*self.tree.get_children())
        for row in self.network_data:
            tag = ""
            if row[5] in ["EVIL TWIN", "THREAT"]:
                tag = "danger"
            elif row[5] == "SUSPECT":
                tag = "warning"
            self.tree.insert("", tk.END, values=row, tags=(tag,))
        self.tree.tag_configure("danger", background="#4a1c1c")
        self.tree.tag_configure("warning", background="#4a3c1c")
        self.show_recommendations()
        self.status_lbl.config(text=f"{len(self.network_data)} networks found")
        threat_list = [row[5] for row in self.network_data if row[5]]
        if threat_list:
            unique_threats = set(threat_list)
            threats_text = ", ".join(unique_threats)
            messagebox.showwarning("Threat Alert", f"Threat detected: {threats_text}. Please review the table for details.")
            self.initiate_additional_checks(threats_text)

    def initiate_additional_checks(self, threat):
        messagebox.showinfo("Advanced Security Check", f"Initiating advanced security check for threat: {threat}")
        try:
            result = subprocess.run(
                ["echo", "Simulating handshake capture and vulnerability scanning..."],
                capture_output=True,
                text=True,
                shell=True
            )
            output = result.stdout
            messagebox.showinfo("Advanced Check Output", output)
        except Exception as e:
            messagebox.showerror("Advanced Check Error", f"An error occurred during advanced security check:\n{e}")

    def get_score(self, security, signal):
        base = {
            "OPEN": 2,
            "WEP": 3,
            "WPA": 6,
            "WPA2": 8,
            "WPA3": 10
        }.get(security, 5)
        if signal < -85:
            base -= 2
        return max(min(base, 10), 0)

    def get_security_type(self, auth):
        if auth is None or auth == const.AKM_TYPE_NONE:
            return "OPEN"
        elif auth == const.AKM_TYPE_WPA:
            return "WPA"
        elif auth == const.AKM_TYPE_WPA2:
            return "WPA2"
        elif hasattr(const, 'AKM_TYPE_WPA3') and auth == const.AKM_TYPE_WPA3:
            return "WPA3"
        else:
            return "UNKNOWN"

    def show_graph(self):
        ssids = [row[0] for row in self.network_data]
        signals = [row[2] for row in self.network_data]
        plt.figure(figsize=(10, 5))
        plt.barh(ssids, signals, color='skyblue')
        plt.xlabel("Signal Strength (dBm)")
        plt.title("WiFi Signal Strengths")
        plt.tight_layout()
        plt.show()

    def export_csv(self):
        if not self.network_data:
            messagebox.showwarning("No Data", "No network data to export. Please run a scan first.")
            return
        try:
            with open("wifi_threat_report.csv", "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Network Name (SSID)",
                    "MAC Address (BSSID)",
                    "Signal",
                    "Security",
                    "Penetration test score",
                    "Threat"
                ])
                for row in self.network_data:
                    writer.writerow(row)
            messagebox.showinfo("Exported", "WiFi report exported to wifi_threat_report.csv")
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred while exporting CSV:\n{e}")

    def show_recommendations(self):
        self.recommend_box.config(state=tk.NORMAL)
        self.recommend_box.delete(1.0, tk.END)
        found_threats = False
        for row in self.network_data:
            threat = row[5]
            if threat:
                found_threats = True
                if threat == "EVIL TWIN":
                    self.recommend_box.insert(tk.END, "\n[EVIL TWIN DETECTED]\n")
                    self.recommend_box.insert(tk.END, "A rogue access point is imitating a known SSID.\n")
                    self.recommend_box.insert(tk.END, "Avoid connecting. Use VPN and verify BSSID.\n")
                elif threat == "THREAT":
                    self.recommend_box.insert(tk.END, "\n[WEAK SECURITY]\n")
                    self.recommend_box.insert(tk.END, "Open or WEP-protected network.\n")
                    self.recommend_box.insert(tk.END, "Avoid usage. Use VPN or secure alternatives.\n")
                elif threat == "SUSPECT":
                    self.recommend_box.insert(tk.END, "\n[WEAK SIGNAL SPOOF]\n")
                    self.recommend_box.insert(tk.END, "Low signal may indicate a spoofed network.\n")
                    self.recommend_box.insert(tk.END, "Do not connect unless verified.\n")
        if not found_threats:
            self.recommend_box.insert(tk.END, "✅ No immediate threats detected. All visible networks appear safe.")
        self.recommend_box.config(state=tk.DISABLED)

    # Hover callback to show threat explanations.
    def on_treeview_motion(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region == "cell":
            col = self.tree.identify_column(event.x)
            if col == "#6":  # Threat column.
                item = self.tree.identify_row(event.y)
                if item:
                    values = self.tree.item(item, "values")
                    threat = values[5] if len(values) > 5 else ""
                    tip_text = ""
                    if threat == "EVIL TWIN":
                        tip_text = "Evil Twin: A rogue access point imitating a legitimate one to intercept data."
                    elif threat == "THREAT":
                        tip_text = "Weak Security: The network is open or uses outdated encryption (WEP)."
                    elif threat == "SUSPECT":
                        tip_text = "Weak Signal Spoof: Low signal might indicate a spoofed network."
                    if tip_text:
                        self.show_tooltip(tip_text, event.x_root + 10, event.y_root + 10)
                        return
        self.hide_tooltip()

    def show_tooltip(self, text, x, y):
        if self.tooltip is None:
            self.tooltip = tk.Toplevel(self.tree)
            self.tooltip.wm_overrideredirect(True)
            label = tk.Label(self.tooltip, text=text, justify="left",
                             background="#ffffe0", relief="solid", borderwidth=1,
                             font=("tahoma", "8", "normal"))
            label.pack(ipadx=1)
            self.tooltip.geometry("+%d+%d" % (x, y))
        else:
            label = self.tooltip.winfo_children()[0]
            if label["text"] != text:
                label.config(text=text)
            self.tooltip.geometry("+%d+%d" % (x, y))

    def hide_tooltip(self):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

    def show_trends(self):
        query = """
            SELECT scan_time, COUNT(*) as total, 
              SUM(CASE WHEN threat != '' THEN 1 ELSE 0 END) as threats 
            FROM scans 
            GROUP BY scan_time 
            ORDER BY scan_time ASC
        """
        self.cursor.execute(query)
        rows = self.cursor.fetchall()
        if not rows:
            messagebox.showinfo("No Historical Data", "No historical logs to analyze.")
            return
        times = [r[0] for r in rows]
        total_counts = [r[1] for r in rows]
        threat_counts = [r[2] for r in rows]
        time_labels = [datetime.fromisoformat(t) for t in times]
        plt.figure(figsize=(10, 6))
        plt.plot(time_labels, total_counts, marker='o', label="Total Networks")
        plt.plot(time_labels, threat_counts, marker='o', label="Threat Networks")
        plt.xlabel("Scan Time")
        plt.ylabel("Count")
        plt.title("Historical Scan Trends")
        plt.legend()
        plt.gcf().autofmt_xdate()
        plt.show()


if __name__ == '__main__':
    if platform.system() != 'Windows':
        print("This tool is designed to run on Windows with pywifi.")
    else:
        root = tk.Tk()
        app = WiFiThreatDetector(root)
        root.mainloop()
