# ENIS
ENIS is an enterprise-grade, live network security intelligence tool designed for real-time infrastructure visualization and attack surface analysis. Unlike static simulations, this engine performs live TCP handshakes, cryptographic audits, and deep web surface inspections to provide an accurate, up-to-the-second view of external digital assets.

Megadriod Innovation Labs 
Enterprise Infrastructure & Attack Surface Mapper
Overview
Megadriod Innovation Labs v3.0 is an enterprise-grade, live network security intelligence tool designed for real-time infrastructure visualization and attack surface analysis. Unlike static simulations, this engine performs live TCP handshakes, cryptographic audits, and deep web surface inspections to provide an accurate, up-to-the-second view of external digital assets.

Key Features (40+ Analytical Metrics)
1. Live Infrastructure Mapping

Dynamic Topology Generation: Visualizes network paths using the Cytoscape.js engine.

IP Classification: Automatically identifies Public, Private, Loopback, and Multicast addresses.

Latency Tracking: Measures exact millisecond (ms) response times for every connection.

Stealth Firewall Detection: Differentiates between closed ports and dropped packets.

2. Deep Service Auditing

Dynamic Service Resolution: Interrogates ports to identify services without hardcoded lists.

Raw Banner Grabbing: Pulls version strings directly from open sockets.

Risk Scoring Engine: Algorithmic grading (Critical, High, Medium, Low) based on protocol exposure.

Service Fingerprinting: Identifies legacy or insecure protocols like FTP and Telnet.

3. Cryptographic & SSL Analysis

TLS Version Auditing: Detects insecure protocols (TLS 1.0/1.1) in real-time.

Cipher Suite Extraction: Identifies the encryption algorithm and bit-strength.

Certificate Intel: Extracts Issuer, Expiry Date, and Subject Alternative Names (SANs).

4. Web Surface Intelligence

HTTP Header Audit: Checks for missing security headers (HSTS, CSP, X-Frame-Options).

WAF Detection: Identifies Cloudflare and other Web Application Firewalls.

Surface Probing: Locates exposed robots.txt, sitemaps, and framework leaks.

5. Interactive SOC Interface

Node Inspector Panel: Interactive sidebar providing deep-dive remediation advice when a node is clicked.

Topology Controls: Switch between Concentric, Grid, and Tree layouts on the fly.

Data Export: Generate JSON-based enterprise audit reports for offline analysis.


6. Local Installation & Setup
Clone the Project
Open your terminal and clone your repository from GitHub.

Install Dependencies
Run the following command to install the required Python packages:
pip install -r requirements.txt

Launch the Core
Start the application using the following command:
python main.py

Access the Lab
Open your browser and navigate to http://localhost:8000.

Usage & Security
This tool is designed for educational and authorized security auditing purposes only. Ensure you have explicit permission before scanning any infrastructure that you do not own.

Megadriod Innovation Labs © 2026
Proprietary Enterprise Security Content
