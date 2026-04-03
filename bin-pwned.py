import os
import subprocess
import time
from requests import post
from rich import print
from rich.progress import Progress
from art import tprint
from packaging.version import Version
from concurrent.futures import ThreadPoolExecutor, as_completed
from packaging.version import InvalidVersion

class binPwned:
    def __init__(self):
        self.base_url = "https://api.osv.dev/v1/query"
        self.delay = 1

    def get_version(self, path):
        try:
            result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=2)
            output = result.stdout.strip() or result.stderr.strip()
            for word in output.split():
                if any(c.isdigit() for c in word) and "." in word:
                    return word
        except:
            return None
        return None

    def query(self, pkg, version_str):
        headers = {"Content-Type": "application/json"}
        payload = {"package": {"name": pkg}, "version": version_str}
        try:
            response = post(self.base_url, headers=headers, json=payload, timeout=5)
        except:
            return []
        if response.status_code != 200:
            return []
        data = response.json()
        affected_cves = []
        for vuln in data.get("vulns", []):
            if self.is_version_affected(vuln, version_str):
                affected_cves.append(vuln)
        return affected_cves

    def is_version_affected(self, vuln, version_str):
        version = Version(version_str)
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                if r["type"] == "SEMVER":
                    events = r.get("events", [])
                    current = None
                    for e in events:
                        if "introduced" in e:
                            current = Version(e["introduced"])
                        elif "fixed" in e and current is not None:
                            fixed = Version(e["fixed"])
                            if current <= version < fixed:
                                return True
                            current = None
        return False


    def scan_bin(self, filename):
        path = os.path.join("/usr/bin", filename)
        if not os.access(path, os.X_OK):
            return None
        version_str = self.get_version(path)
        if not version_str:
            return None
        try:
            Version(version_str)
        except InvalidVersion:
            return None
        cves = self.query(filename, version_str)
        time.sleep(self.delay)
        if cves:
            return f"[❌] {filename} ({version_str}):\n" + "\n".join(
                f"   - [yellow]{v['id']}[/yellow]: {v.get('summary','No summary')}" for v in cves
            )
        return f"[✅] {filename} ({version_str}): Safe"

    def scan_usr_bin(self):
        tprint("bin-pwned?")
        usr_bin = os.listdir("/usr/bin")
        results = []
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning binaries...", total=len(usr_bin))
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_bin = {executor.submit(self.scan_bin, f): f for f in usr_bin}
                for i, future in enumerate(as_completed(future_to_bin), 1):
                    res = future.result()
                    if res:
                        results.append(res)
                        print(res)
                    progress.update(task, advance=1)
        
        print(f"\n[green]Scan complete! {len(results)} binaries checked.[/green]")

def main():
    bp = binPwned()
    bp.scan_usr_bin()

if __name__ == "__main__":
    main()