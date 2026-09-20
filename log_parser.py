import os

RESET, RED, GREEN, YELLOW = "\033[0m", "\033[31m", "\033[32m", "\033[33m"

def analyze_log(file_path, thresold = 3):
    
    #check if file exists
    if not os.path.exists(file_path):
        print(f"{RED}[ERROR] File not found. {RESET}")
        return
    
    sus_ips = {}

    #Counting total records.
    with open(file_path, "r") as f:
        total_log = sum(1 for line in f)

    if total_log == 0:
        print("File is empty.")
        return
    
    print(f"Starting log analysis (TOTAL {total_log} RECORDS)" .center(20 + 20,'='))
    with open(file_path, "r") as file:
        for index, line in enumerate(file,1):
            parts = line.split()
            if not line:        #If the line is empty py will skip it.
                continue         

            parts =line.split()
            if len(parts) < 5:  #Ignores incomplete logs. So that the script wont crash.
                continue

            ip_address = parts[0]
            status_Code = parts[4]

            print(f"[{index}/{total_log}] Inspecting ip: {ip_address} | Status code: {status_Code}")

            #check for failed attempts.
            if status_Code in ("404", "401"):
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

#Main interface, If the script is imported the interactive prompt wont run automatically.
if __name__ == "__main__":
    print(f"{GREEN}====Security Log Parser CLI===={RESET}")
    log_file = input("Enter path to log file (Press enter for defauly 'sample.log'): ")

    if not log_file:
        log_file = "sample.log"
    
analyze_log(log_file)