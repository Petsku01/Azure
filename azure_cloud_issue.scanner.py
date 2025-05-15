# Python version 1.0.1

# Works in test enviroment

# Not for prod

import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from azure.identity import ClientSecretCredential, AuthenticationFailedException
from azure.mgmt.servicehealth import ServiceHealthManagementClient
from azure.core.exceptions import HttpResponseError
from datetime import datetime
from dateutil import tz
import logging

# Setup loggings
logging.basicConfig(filename="azure_scanner.log", level=logging.INFO)

# Azure credentials
TENANT_ID = os.getenv("AZURE_TENANT_ID", "your-tenant-id")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "your-client-id")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "your-client-secret")
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "your-subscription-id")

# Validate credentials
if any("your-" in x for x in [TENANT_ID, CLIENT_ID, CLIENT_SECRET, SUBSCRIPTION_ID]):
    raise ValueError("Azure credentials are not configured. Set environment variables or update placeholders.")

# Initialize credentials and client
credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
service_health_client = ServiceHealthManagementClient(credential, SUBSCRIPTION_ID)

class AzureHealthScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Azure Cloud Health Scanner")
        self.root.geometry("900x600")

        # Scanning state
        self.is_scanning = False
        self.poll_interval = 300000  # 5 minutes in ms
        self.previous_issues = set()  # Tracks issue IDs for new issue detection
        self.current_issues = []  # Store current issues for saving

        # GUI elements
        self.status_label = tk.Label(root, text="Status: Stopped")
        self.status_label.pack(pady=5)

        self.toggle_button = tk.Button(root, text="Start Scanning", command=self.toggle_scanning)
        self.toggle_button.pack(pady=10)

        # Treeview for displaying issues
        columns = ("Type", "Title", "Status", "Service", "Region", "Last Update", "Description")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=20)
        self.tree.pack(pady=10, fill=tk.BOTH, expand=True)

        # Set column headings and widths
        self.tree.heading("Type", text="Type")
        self.tree.heading("Title", text="Title")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Service", text="Service")
        self.tree.heading("Region", text="Region")
        self.tree.heading("Last Update", text="Last Update")
        self.tree.heading("Description", text="Description")
        self.tree.column("Type", width=100)
        self.tree.column("Title", width=200)
        self.tree.column("Status", width=100)
        self.tree.column("Service", width=150)
        self.tree.column("Region", width=100)
        self.tree.column("Last Update", width=150)
        self.tree.column("Description", width=300)

        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(root, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Tags for highlighting new issues
        self.tree.tag_configure("new", background="lightcoral")

        self.save_button = tk.Button(root, text="Save Report", command=self.save_report)
        self.save_button.pack(pady=10)

    def toggle_scanning(self):
        """Start or stop continuous scanning."""
        if self.is_scanning:
            self.is_scanning = False
            self.toggle_button.config(text="Start Scanning")
            self.status_label.config(text="Status: Stopped")
            logging.info("Scanning stopped")
        else:
            self.is_scanning = True
            self.toggle_button.config(text="Stop Scanning")
            self.status_label.config(text=f"Status: Scanning (Last update: {datetime.now(tz.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')})")
            self.scan_azure_health()
            self.schedule_scan()
            logging.info("Scanning started")

    def schedule_scan(self):
        """Schedule the next scan if scanning is active."""
        if self.is_scanning:
            self.root.after(self.poll_interval, self.scan_azure_health)

    def scan_azure_health(self):
        """Scan Azure Service Health and update treeview."""
        try:
            logging.info(f"Starting scan at {datetime.now(tz.UTC)}")
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.current_issues = []
            current_issues_ids = set()

            incidents = service_health_client.service_issues.list()
            for incident in incidents:
                issue_id = incident.name
                current_issues_ids.add(issue_id)
                is_new = issue_id not in self.previous_issues
                values = (
                    "Incident",
                    incident.properties.title or "Unknown",
                    incident.properties.status or "Unknown",
                    incident.properties.service or "Unknown",
                    incident.properties.region or "Unknown",
                    str(incident.properties.last_update_time or "N/A"),
                    incident.properties.summary[:200] if incident.properties.summary else "N/A"
                )
                self.current_issues.append((
                    values[0], values[1], values[2], values[3], values[4], values[5],
                    incident.properties.summary or "N/A"  # Full description for saving
                ))
                self.tree.insert("", tk.END, values=values, tags=("new" if is_new else ""))

            maintenance = service_health_client.planned_maintenances.list()
            for event in maintenance:
                issue_id = event.name
                current_issues_ids.add(issue_id)
                is_new = issue_id not in self.previous_issues
                values = (
                    "Maintenance",
                    event.properties.title or "Unknown",
                    event.properties.status or "Unknown",
                    event.properties.service or "Unknown",
                    event.properties.region or "Unknown",
                    f"{event.properties.scheduled_start_time or 'N/A'} to {event.properties.scheduled_end_time or 'N/A'}",
                    event.properties.summary[:200] if event.properties.summary else "N/A"
                )
                self.current_issues.append((
                    values[0], values[1], values[2], values[3], values[4], values[5],
                    event.properties.summary or "N/A"  # Full description for saving
                ))
                self.tree.insert("", tk.END, values=values, tags=("new" if is_new else ""))

            self.previous_issues = current_issues_ids
            self.status_label.config(text=f"Status: Scanning (Last update: {datetime.now(tz.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')})")
            self.schedule_scan()
            logging.info(f"Scan completed, found {len(self.current_issues)} issues")

        except HttpResponseError as e:
            logging.error(f"API error: {str(e)}")
            if e.status_code == 429:
                messagebox.showwarning("Warning", "API rate limit exceeded. Retrying after 1 minute.")
                self.root.after(60000, self.scan_azure_health)
            else:
                self.is_scanning = False
                self.toggle_button.config(text="Start Scanning")
                self.status_label.config(text="Status: Stopped (API Error)")
                messagebox.showerror("Error", f"Azure API error: {str(e)}. Check permissions or subscription ID.")
        except AuthenticationFailedException as e:
            logging.error(f"Authentication error: {str(e)}")
            self.is_scanning = False
            self.toggle_button.config(text="Start Scanning")
            self.status_label.config(text="Status: Stopped (Authentication Error)")
            messagebox.showerror("Error", f"Authentication failed: {str(e)}. Verify CLIENT_ID, CLIENT_SECRET, and TENANT_ID.")
        except (ValueError, ConnectionError) as e:
            logging.error(f"Scan error: {str(e)}")
            self.is_scanning = False
            self.toggle_button.config(text="Start Scanning")
            self.status_label.config(text="Status: Stopped (Error)")
            messagebox.showerror("Error", f"Failed to scan Azure health: {str(e)}. Check network or configuration.")

    def save_report(self):
        """Save the current issues to a text file."""
        if not self.current_issues:
            messagebox.showwarning("Warning", "No issues to save. Run a scan first.")
            return

        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                initialfile=f"azure_health_report_{datetime.now(tz.UTC).strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if filename:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(f"Azure Cloud Health Report\nGenerated: {datetime.now(tz.UTC).isoformat()}\n{'='*50}\n\n")
                    for issue in self.current_issues:
                        f.write(f"Type: {issue[0]}\n")
                        f.write(f"Title: {issue[1]}\n")
                        f.write(f"Status: {issue[2]}\n")
                        f.write(f"Service: {issue[3]}\n")
                        f.write(f"Region: {issue[4]}\n")
                        f.write(f"Last Update: {issue[5]}\n")
                        f.write(f"Description: {issue[6]}\n")
                        f.write("\n")
                messagebox.showinfo("Success", f"Report saved to {filename}")
                logging.info(f"Report saved to {filename}")
        except IOError as e:
            logging.error(f"Save error: {str(e)}")
            messagebox.showerror("Error", f"Failed to save report: {str(e)}. Check disk space or permissions.")

def main():
    root = tk.Tk()
    app = AzureHealthScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
