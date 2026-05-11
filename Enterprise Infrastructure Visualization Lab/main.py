from fastapi import FastAPI, Request, Query
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import socket
import ssl
import urllib.request
import urllib.error
import concurrent.futures
import time
import ipaddress
import uvicorn

app = FastAPI(title="Megadriod Innovation Labs - Live Infrastructure Scanner")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443]

def get_service_name(port: int):
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "UNKNOWN"

def grab_banner(ip: str, port: int):
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:50] + "..." if len(banner) > 50 else banner
    except Exception:
        return None

def get_ssl_info(ip: str):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname=ip) as ss:
                cert = ss.getpeercert(binary_form=False)
                issuer = dict(x[0] for x in cert.get('issuer', []))
                sans = [x[1] for x in cert.get('subjectAltName', [])]
                cipher = ss.cipher() # Feature 25: Cipher Suite
                return {
                    "issuer": issuer.get('organizationName', 'Unknown'),
                    "expires": cert.get('notAfter', 'Unknown'),
                    "sans": sans[:3],
                    "tls_version": ss.version(), # Feature 24: TLS Version
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "secret_bits": cipher[2] if cipher else 0 # Feature 26: Bit strength
                }
    except Exception:
        return None

def check_web_surface(url: str, endpoint: str):
    """Features 29, 30: Surface Discovery"""
    try:
        req = urllib.request.Request(url + endpoint, method="HEAD")
        with urllib.request.urlopen(req, timeout=2, context=ssl._create_unverified_context()) as response:
            return response.getcode() == 200
    except Exception:
        return False

def get_http_info(ip: str, port: int):
    protocol = "https" if port in [443, 8443] else "http"
    url = f"{protocol}://{ip}:{port}"
    info = {
        "status": None, "server": None, "title": None, "sec_headers": [], 
        "waf": None, "methods": "", "robots": False, "sitemap": False
    }
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Feature 27: OPTIONS Request
        try:
            opt_req = urllib.request.Request(url, method="OPTIONS")
            with urllib.request.urlopen(opt_req, timeout=2, context=ctx) as opt_res:
                info["methods"] = opt_res.info().get("Allow", "GET, POST")
        except Exception:
            pass

        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3, context=ctx) as response:
            info["status"] = response.getcode()
            headers = response.info()
            info["server"] = headers.get("Server", "Hidden")
            
            # WAF & Framework Fingerprinting (Features 30, 31)
            if "cf-ray" in headers or "cloudflare" in str(info["server"]).lower(): info["waf"] = "Cloudflare"
            if headers.get("X-Powered-By"): info["sec_headers"].append(f"Leaks Framework: {headers.get('X-Powered-By')}")

            # Advanced Header Audits (Features 32-35)
            if "Strict-Transport-Security" not in headers: info["sec_headers"].append("Missing HSTS")
            if "X-Frame-Options" not in headers: info["sec_headers"].append("Missing X-Frame-Options")
            if "X-Content-Type-Options" not in headers: info["sec_headers"].append("Missing Content-Type-Options")
            if headers.get("Access-Control-Allow-Origin") == "*": info["sec_headers"].append("Insecure CORS (*)")
            
            cookies = headers.get("Set-Cookie", "")
            if cookies and "Secure" not in cookies: info["sec_headers"].append("Insecure Cookie (Missing Secure)")

            html = response.read(2048).decode('utf-8', errors='ignore')
            if "<title>" in html.lower():
                title_start = html.lower().find("<title>") + 7
                title_end = html.lower().find("</title>")
                info["title"] = html[title_start:title_end].strip()
                
        # Probes
        info["robots"] = check_web_surface(url, "/robots.txt")
        info["sitemap"] = check_web_surface(url, "/sitemap.xml")

    except urllib.error.HTTPError as e:
        info["status"] = e.code
    except Exception:
        pass
    
    return info if info["status"] else None

def scan_port(ip: str, port: int):
    start_time = time.time()
    try:
        with socket.create_connection((ip, port), timeout=1.5):
            latency = round((time.time() - start_time) * 1000)
            service = get_service_name(port)
            
            risk = "Low"
            if port in [21, 23]: risk = "Critical"
            elif port in [3306, 3389, 445, 139]: risk = "High"
            
            data = {"port": port, "service": service, "latency_ms": latency, "risk": risk, "state": "Open"}
            
            if port in [80, 443, 8080, 8443]:
                data["http"] = get_http_info(ip, port)
            else:
                data["banner"] = grab_banner(ip, port)
                
            return data
    except socket.timeout:
        # Feature 22: Stealth Drop Detection
        return {"port": port, "service": get_service_name(port), "risk": "None", "state": "Filtered/Dropped"}
    except ConnectionRefusedError:
        return None
    except Exception:
        return None

def run_deep_scan(target: str):
    scan_start = time.time()
    ip = socket.gethostbyname(target)
    
    try: ptr = socket.gethostbyaddr(ip)[0]
    except socket.herror: ptr = "No Reverse DNS Record"

    # Feature 21: IP Classification
    ip_obj = ipaddress.ip_address(ip)
    ip_class = "Private/Internal" if ip_obj.is_private else "Public/External"
    if ip_obj.is_loopback: ip_class = "Loopback"

    results = {
        "target": target,
        "resolved_ip": ip,
        "ip_class": ip_class,
        "reverse_dns": ptr,
        "ssl_data": get_ssl_info(ip),
        "open_ports": [],
        "filtered_ports": 0
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in SCAN_PORTS]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                if res["state"] == "Open":
                    results["open_ports"].append(res)
                elif res["state"] == "Filtered/Dropped":
                    results["filtered_ports"] += 1
                
    results["open_ports"] = sorted(results["open_ports"], key=lambda x: x["port"])
    results["scan_duration_ms"] = round((time.time() - scan_start) * 1000) # Feature 23
    return results

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={})

@app.get("/api/v1/live-scan")
async def api_scan(target: str = Query(..., description="Target to scan")):
    try:
        raw_data = run_deep_scan(target)
        
        nodes = [{"data": {"id": "scanner", "label": "Megadriod Core", "type": "source", "desc": "The scanning engine initiating the requests."}}]
        edges = []
        
        if raw_data["open_ports"]:
            nodes.append({"data": {"id": "target", "label": raw_data["resolved_ip"], "type": "target", "desc": f"Resolved IP Address. Class: {raw_data['ip_class']}"}})
            edges.append({"data": {"source": "scanner", "target": "target", "label": f"{raw_data['scan_duration_ms']}ms Sweep"}})
            
            for p in raw_data["open_ports"]:
                n_id = f"port_{p['port']}"
                desc_text = f"Exposed {p['service']} service."
                if "http" in p and p["http"]: 
                    desc_text += f" Running {p['http'].get('server', 'Unknown')}."
                
                nodes.append({"data": {
                    "id": n_id, "label": f"Port {p['port']}\n({p['service']})", 
                    "type": "service", "risk": p["risk"], "port": p["port"], "service": p["service"], "desc": desc_text
                }})
                edges.append({"data": {"source": "target", "target": n_id, "label": f"{p['latency_ms']}ms"}})
                
        raw_data["graph"] = {"nodes": nodes, "edges": edges}
        return raw_data
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000)