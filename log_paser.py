raw_logs = [
    "192.168.1.10 [20/Sep/2026] GET /index.html 200",
    "192.168.1.15 [20/Sep/2026] GET /about.html 200",
    "10.0.0.45 [20/Sep/2026] POST /login 401",  # 401 means Unauthorized (Failed Login)
    "10.0.0.45 [20/Sep/2026] POST /login 401",
    "10.0.0.45 [20/Sep/2026] POST /login 401",
    "192.168.1.10 [20/Sep/2026] GET /images/logo.png 200",
    "10.0.0.45 [20/Sep/2026] GET /admin_dashboard 404", # 404 means Not Found
    "10.0.0.45 [20/Sep/2026] GET /config.bak 404",
    "192.168.1.20 [20/Sep/2026] GET /contact 200"
]

RESET, RED, GREEN, YELLOW = "\033[0m", "\033[31m", "\033[32m", "\033[33m"

def analyze_log(logs, thresold = 3):
    sus_ips = {}
    total_logs = len(logs)

    print(f"Starting log analysis (TOTAL {total_logs} RECORDS)" .center(20 + 20,'='))

    for index, line in enumerate(logs,1):
        parts = line.split()                
        ip_address = parts[0]
        status_Code = parts[4]

        print(f"[{index}/{total_logs}] Inspecting ip: {ip_address} | Status code: {status_Code}")

        #check for failed attempts.
        if status_Code == "404" or status_Code == "401":
            if ip_address in sus_ips:
                sus_ips[ip_address] +=1
            else:
                sus_ips[ip_address] = 1
        #Notify user
            print(f"{YELLOW}[!]{RESET} Suspicious activity from {ip_address}  (TOTAL: {sus_ips[ip_address]})\n")

    #Results
    print("Threat Report".center(20+20,'='))
    for ip,fail_count in sus_ips.items():
        if fail_count >= thresold:
            print(f"{RED}[ALERT]{RESET}IP {ip} flagged! {fail_count} failed attempt detected.")

analyze_log(raw_logs)