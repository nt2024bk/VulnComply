import tkinter as tk
from tkinter import filedialog, scrolledtext
import json
from openpyxl import Workbook

class ComplianceCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PCI Vulnerability Compliance Checker")
        self.root.geometry("800x600")

        self.vulnerabilities = []
        self.pci_requirements = []
        self.compliance_results = []

        # Output widget to display messages
        self.output_widget = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20)
        self.output_widget.grid(row=0, column=0, columnspan=4, padx=10, pady=10)

        # Buttons for file upload, compliance check, and export
        tk.Button(self.root, text="Load Vulnerability File", command=self.load_vulnerability_file).grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        tk.Button(self.root, text="Load PCI Compliance File", command=self.load_compliance_file).grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        tk.Button(self.root, text="Check Compliance", command=self.check_compliance).grid(row=1, column=2, padx=10, pady=10, sticky="ew")
        tk.Button(self.root, text="Export to Excel", command=self.export_to_excel).grid(row=1, column=3, padx=10, pady=10, sticky="ew")

        # Adjust grid column weights for resizing
        for i in range(4):
            self.root.grid_columnconfigure(i, weight=1)

    def load_vulnerability_file(self):
        """Load a vulnerability file (JSON)."""
        try:
            filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
            if filename:
                with open(filename, 'r') as file:
                    self.vulnerabilities = json.load(file)
                self.output_message(f"Loaded vulnerabilities from {filename}")
        except Exception as e:
            self.output_message(f"Error: Could not load vulnerability file: {str(e)}")

    def load_compliance_file(self):
        """Load PCI compliance file (JSON)."""
        try:
            filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
            if filename:
                with open(filename, 'r') as file:
                    self.pci_requirements = json.load(file)
                self.output_message(f"Loaded PCI compliance requirements from {filename}")
        except Exception as e:
            self.output_message(f"Error: Could not load PCI compliance file: {str(e)}")

    def check_compliance(self):
        """Check vulnerabilities against PCI compliance requirements and update results in the output widget."""
        if not self.vulnerabilities or not self.pci_requirements:
            self.output_message("Error: Please load both vulnerability and PCI compliance files.")
            return
        
        self.compliance_results = []  # Reset previous results
        for vuln in self.vulnerabilities:
            related_requirements = [req for req in self.pci_requirements if req['id'] == vuln['id']]
            for req in related_requirements:
                result = {
                    "id": vuln['id'],
                    "description": vuln.get('description', 'No description'),
                    "severity": vuln.get('severity', 'Unknown'),
                    "pci_requirement": req['id'],
                    "status": "Non-compliant" if vuln['severity'] not in req['acceptable_severities'] else "Compliant",
                    "recommendation": req.get('recommendation', 'No recommendation')
                }
                self.compliance_results.append(result)
                status_message = f"Vulnerability {vuln['id']} is {result['status']} with requirement {req['id']}."
                self.output_message(status_message)

        self.output_message("\nCompliance check completed.")

    def export_to_excel(self):
        """Export compliance results to an Excel spreadsheet."""
        try:
            file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx"), ("All Files", "*.*")])
            if not file_path:
                self.output_message("Export canceled.")
                return

            wb = Workbook()
            ws = wb.active
            ws.title = "Compliance Results"

            # Define headers
            headers = ["Vulnerability ID", "Description", "Severity", "PCI Requirement Violated", "Compliance Status", "Recommendation"]
            ws.append(headers)

            # Add compliance results
            for result in self.compliance_results:
                row = [
                    result["id"],
                    result["description"],
                    result["severity"],
                    result["pci_requirement"],
                    result["status"],
                    result["recommendation"]
                ]
                ws.append(row)

            # Save the Excel file
            wb.save(file_path)
            self.output_message(f"Results exported to {file_path}")
        except Exception as e:
            self.output_message(f"Error: Could not export to Excel: {str(e)}")

    def output_message(self, message):
        """Output messages to the user in the scrolled text widget."""
        self.output_widget.insert(tk.END, f"{message}\n")
        self.output_widget.yview(tk.END)

def main():
    root = tk.Tk()
    app = ComplianceCheckerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
