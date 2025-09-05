import asyncio
import json
import logging
import os
import random
import re
import ssl
import time
import httpx
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, unquote, quote

# Custom exceptions
class RateLimitException(Exception):
    """Custom exception to indicate a 429 rate-limit error."""
    pass

class PersistentServerException(Exception):
    """Custom exception for repeated 5xx server errors."""
    pass

# Core dependencies


# Browser automation
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# CAPTCHA solving using CapSolver
# No additional imports needed - using httpx which is already imported

# Configure logging
class SafeStreamHandler(logging.StreamHandler):
    """Stream handler that removes emoji characters for Windows compatibility"""
    def emit(self, record):
        try:
            # Remove emoji characters from the message
            if hasattr(record, 'msg') and isinstance(record.msg, str):
                record.msg = re.sub(r'[^\x00-\x7F]+', '[EMOJI]', record.msg)
            super().emit(record)
        except UnicodeEncodeError:
            # Fallback: create a simple ASCII message
            record.msg = "Logging message with encoding issues"
            super().emit(record)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('goethe_api_bot.log', encoding='utf-8'),
        SafeStreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class CaptchaSolver:
    """CAPTCHA solving service integration for CapSolver, supporting both v2 and v3."""
    CREATE_TASK_URL = "https://api.capsolver.com/createTask"
    GET_TASK_RESULT_URL = "https://api.capsolver.com/getTaskResult"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = httpx.Client(timeout=180) # Increased timeout for long-running tasks
        if not self.api_key:
            logger.error("[CAPSOLVER] API key is missing. Captcha solving will fail.")
            raise ValueError("CapSolver API key is required.")

    def __del__(self):
        """Cleanup httpx client when object is destroyed"""
        try:
            if hasattr(self, 'client'):
                self.client.close()
        except:
            pass

    def solve_recaptcha(self, sitekey: str, page_url: str, action: Optional[str] = None, min_score: float = 0.7, is_invisible: bool = False) -> Optional[str]:
        """
        Solves Google reCAPTCHA v2 or v3 Enterprise using CapSolver.

        Args:
            sitekey: The reCAPTCHA sitekey from the website.
            page_url: The URL where the reCAPTCHA is present.
            action: The 'action' string for reCAPTCHA v3. If provided, a v3 task is created.
            min_score: The desired minimum score for a v3 solution.
            is_invisible: Set to True if the reCAPTCHA is invisible.
        Returns:
            The g-recaptcha-response token, or None if solving fails.
        """
        task_details = {
            "websiteURL": page_url,
            "websiteKey": sitekey,
        }

        if action:
            logger.info(f"[CAPSOLVER] Solving reCAPTCHA v3 Enterprise with action: '{action}'")
            task_details["type"] = "ReCaptchaV3TaskProxyLess"
            task_details["pageAction"] = action
            task_details["minScore"] = min_score
        else:
            logger.info(f"[CAPSOLVER] Solving reCAPTCHA v2...")
            task_details["type"] = "ReCaptchaV2TaskProxyLess"
            if is_invisible:
                task_details["isInvisible"] = True

        create_task_payload = {
            "clientKey": self.api_key,
            "task": task_details
        }
        
        try:
            # 1. Create the task
            response = self.client.post(self.CREATE_TASK_URL, json=create_task_payload)
            response.raise_for_status()
            result = response.json()

            if result.get("errorId") != 0:
                error_desc = result.get('errorDescription', 'Unknown error')
                logger.error(f"[CAPSOLVER] Failed to create task. Error: {error_desc}")
                return None
            
            task_id = result.get("taskId")
            if not task_id:
                logger.error("[CAPSOLVER] Failed to get task ID from response.")
                return None

            logger.info(f"[CAPSOLVER] Task created successfully with ID: {task_id}")

            # 2. Poll for the result
            get_result_payload = {"clientKey": self.api_key, "taskId": task_id}
            
            start_time = time.time()
            while time.time() - start_time < 180: # 3-minute timeout
                time.sleep(5)
                
                result_response = self.client.post(self.GET_TASK_RESULT_URL, json=get_result_payload)
                result_response.raise_for_status()
                task_result = result_response.json()

                if task_result.get("errorId") != 0:
                    error_desc = task_result.get('errorDescription', 'Unknown error')
                    logger.error(f"[CAPSOLVER] Polling failed. Error: {error_desc}")
                    return None

                status = task_result.get("status")
                logger.info(f"[CAPSOLVER] Current task status: {status}")

                if status == "ready":
                    solution = task_result.get("solution", {})
                    g_recaptcha_response = solution.get("gRecaptchaResponse")
                    if g_recaptcha_response:
                        logger.info("[CAPSOLVER] ✅ reCAPTCHA solved successfully!")
                        return g_recaptcha_response
                    else:
                        logger.error("[CAPSOLVER] Task is ready but solution is missing.")
                        return None
                elif status == "failed":
                    logger.error("[CAPSOLVER] Task failed.")
                    return None
            
            logger.error("[CAPSOLVER] Task timed out after 3 minutes.")
            return None

        except httpx.HTTPStatusError as e:
            logger.error(f"[CAPSOLVER] HTTP error: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"[CAPSOLVER] An unexpected error occurred: {e}")
            return None

class GoetheAPIBot:
    """High-speed Goethe Institut booking bot using direct API calls with enhanced session management"""

    # --- ADD THIS CONSTANT ---
    BATTLE_WINDOW_SECONDS = 30 # How long to relentlessly try to break through the initial server errors.

    def __init__(self, captcha_api_key: str, captcha_service: str = "capsolver", 
                 proxy: Optional[str] = None, stop_signal: asyncio.Event = None, log_prefix: str = "",
                 recaptcha_v3_action: Optional[str] = None): # ADD a new parameter for v3 action
        self.proxy = proxy
        self.stop_signal = stop_signal
        self.log_prefix = log_prefix
        self.recaptcha_v3_action = recaptcha_v3_action # STORE the action
        # Enhanced TLS configuration for better security
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        # Connection limits for better resource management
        limits = httpx.Limits(
            max_keepalive_connections=10,
            max_connections=20,
            keepalive_expiry=30.0
        )
        # Generate random user agent to avoid detection
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'
        ]
        selected_user_agent = random.choice(user_agents)
        
        # --- PROXY CONFIGURATION START (Backward-Compatible Version) ---
        proxy_url = None
        if proxy:
            # Improved logging to show the unique part of the proxy username
            proxy_display = proxy.split('@')[-1] # Fallback
            match = re.search(r'(ip-[\d\.-]+)', proxy)
            if match:
                proxy_display = f"...{match.group(1)}@{proxy.split('@')[-1]}"
            
            self._log(logging.INFO, f"[PROXY] Bot instance configured to use proxy: {proxy_display}")
            proxy_url = proxy
        else: # ADD THIS ELSE BLOCK
            self._log(logging.INFO, "[PROXY] Bot instance running without a proxy (using server IP).")
        # --- PROXY CONFIGURATION END ---
        
        # HTTP client with enhanced session management and anti-bot detection
        client_kwargs = {
            "timeout": httpx.Timeout(60.0, pool=120.0),
            "limits": limits,
            "verify": ssl_context,
            "headers": {
                'User-Agent': selected_user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'en-US,en;q=0.9,de;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Cache-Control': 'no-cache',
                'DNT': '1'
            },
            "follow_redirects": True,
            "cookies": httpx.Cookies()  # Initialize empty cookie jar
        }
        
        # Only add the proxy argument if a proxy is provided
        if proxy_url:
            client_kwargs["proxy"] = proxy_url  # <--- THIS IS THE FIX FOR OLDER HTTPx
            
        self.session = httpx.AsyncClient(**client_kwargs)
        # CAPTCHA solver (now directly uses CapSolver)
        try:
            self.captcha_solver = CaptchaSolver(api_key=captcha_api_key)
        except ValueError:
            self.captcha_solver = None # Bot can continue, but CAPTCHA pages will fail
        # Enhanced session tracking
        self.cookies = {}
        self.coesessionid = None
        self.tgc_cookie = None
        self.jsessionid = None
        self.session_established = False
        
        # URL tracking for proper relative URL resolution
        self.current_base = 'https://www.goethe.de/coe/'
        self.current_url = None

        # URLs and session data
        self.base_url = 'https://www.goethe.de'
        self.login_base = 'https://login.goethe.de'
        self.current_exam_url = None

        # Redirect handling for BOOK FOR MYSELF fixes
        self.login_redirect_url = None
        self.booking_service_url = None

        # Anti-bot detection settings
        self.request_count = 0
        self.last_request_time = 0
        self.min_request_delay = 0.5  # Minimum delay between requests
        self.max_request_delay = 2.0  # Maximum delay between requests

        # Request retry settings
        self.max_retries = 3
        self.retry_backoff = 2.0

        self._log(logging.INFO, f"[INIT] Bot initialized with User-Agent: {selected_user_agent[:50]}...")
        self._log(logging.INFO, f"[INIT] SSL context configured with secure ciphers")
        self._log(logging.INFO, f"[INIT] Connection limits: {limits.max_connections} max, {limits.max_keepalive_connections} keepalive")
        self._log(logging.INFO, f"[INIT] Anti-bot settings: delay {self.min_request_delay}-{self.max_request_delay}s, max retries {self.max_retries}")
        
        # Final booked modules tracking for accurate confirmation
        self.final_booked_modules = []
        
        # For storing modules data
        self.selected_modules = []

    def _log(self, level: int, message: str):
        """Logs a message with the instance's prefix."""
        logger.log(level, f"{self.log_prefix}{message}")

    def adjust_anti_bot_settings(self, aggressiveness: str = "moderate") -> None:
        """Adjust anti-bot detection settings based on aggressiveness level"""
        if aggressiveness == "low":
            self.min_request_delay = 0.3
            self.max_request_delay = 1.0
            self.max_retries = 2
        elif aggressiveness == "moderate":
            self.min_request_delay = 0.5
            self.max_request_delay = 2.0
            self.max_retries = 3
        elif aggressiveness == "high":
            self.min_request_delay = 1.0
            self.max_request_delay = 4.0
            self.max_retries = 5
        elif aggressiveness == "stealth":
            self.min_request_delay = 2.0
            self.max_request_delay = 8.0
            self.max_retries = 7

        self._log(logging.INFO, f"[ANTI-BOT] Settings adjusted to {aggressiveness}: delay {self.min_request_delay}-{self.max_request_delay}s, retries {self.max_retries}")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        try:
            await self.session.aclose()
        except Exception as e:
            logger.warning(f"[CLEANUP] Session cleanup failed: {e}")

    def _parse_proxy(self) -> Optional[Dict[str, str]]:
        """Parses a proxy URL string into a dictionary for Playwright."""
        if not self.proxy:
            return None
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.proxy)
            
            # Add validation
            if not parsed.hostname or not parsed.port:
                self._log(logging.ERROR, f"[PROXY-PARSE] Invalid proxy format: {self.proxy}")
                return None
                
            proxy_dict = {
                "server": f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
            }
            if parsed.username:
                proxy_dict["username"] = parsed.username
            if parsed.password:
                proxy_dict["password"] = parsed.password
            
            self._log(logging.INFO, f"[PROXY-PARSE] Successfully parsed proxy for browser: {proxy_dict['server']}")
            return proxy_dict
        except Exception as e:
            self._log(logging.ERROR, f"[PROXY-PARSE] Failed to parse proxy: {e}")
            return None


    async def _smart_delay(self) -> None:
        """Implement smart delay to avoid bot detection"""
        # Small random delay between requests for anti-bot protection
        delay = random.uniform(self.min_request_delay, self.max_request_delay)
        if delay > 0:
            await asyncio.sleep(delay)

    def _preserve_session_cookies(self) -> None:
        """Preserve ALL critical session cookies without selective deletion"""
        cookie_dict = dict(self.session.cookies)
        
        # List of critical cookies that must be preserved
        critical_cookies = [
            'coesessionid', 'JSESSIONID', 'TGC', 
            'CFID', 'CFTOKEN', 'CAS_GI_GW_CHECK_DONE'
        ]
        
        for cookie_name in critical_cookies:
            if cookie_name in cookie_dict:
                cookie_value = cookie_dict[cookie_name]
                # Store in instance variables for restoration
                setattr(self, f'preserved_{cookie_name.lower()}', cookie_value)
                self._log(logging.DEBUG, f"[COOKIE] Preserved {cookie_name}: {cookie_value[:20]}...")
        
        # Mark session as established
        if 'coesessionid' in cookie_dict or 'JSESSIONID' in cookie_dict:
            self.session_established = True
            self._log(logging.DEBUG, "[SESSION] Session established with preserved cookies")




    def _cleanup_tgc_cookies(self) -> None:
        """Only cleanup TGC cookies when there are actual duplicates"""
        try:
            tgc_cookies = [c for c in self.session.cookies.jar if c.name == 'TGC']
            
            # Only cleanup if more than 2 TGC cookies (allow some redundancy)
            if len(tgc_cookies) > 2:
                logger.info(f"[TGC-CLEANUP] Found {len(tgc_cookies)} TGC cookies, reducing to 1")
                
                # Sort by expiry time (most recent first)
                # Treat None expiry as 0 for sorting
                tgc_cookies.sort(key=lambda c: c.expires if c.expires else float('inf'), reverse=True)
                
                # Keep the most recent one
                latest_tgc = tgc_cookies[0]
                logger.info(f"[TGC-CLEANUP] Keeping TGC from domain: {latest_tgc.domain}")
                
                # Create new cookie jar
                new_jar = httpx.Cookies()
                
                # Copy all non-TGC cookies
                for cookie in self.session.cookies.jar:
                    if cookie.name != 'TGC':
                        new_jar.set(
                            cookie.name,
                            cookie.value,
                            domain=cookie.domain,
                            path=cookie.path
                        )
                
                # Add only the latest TGC
                new_jar.set(
                    'TGC',
                    latest_tgc.value,
                    domain=latest_tgc.domain,
                    path=latest_tgc.path
                )
                
                # Replace the cookie jar
                self.session.cookies = new_jar
                logger.info(f"[TGC-CLEANUP] Cleaned: kept 1 TGC, removed {len(tgc_cookies)-1} duplicates")
            else:
                logger.debug("[TGC-CLEANUP] No cleanup needed")
                return
                
        except Exception as e:
            import traceback
            logger.error(f"[TGC-CLEANUP] Error: {e}")
            logger.debug(f"[TRACEBACK] {traceback.format_exc()}")
            # Fallback: create new cookie jar keeping non-TGC cookies
            new_jar = httpx.Cookies()
            for cookie in self.session.cookies.jar:
                if cookie.name != 'TGC':
                    new_jar.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)
            self.session.cookies = new_jar



    def _verify_tgc_state(self, context: str = "") -> None:
        """Verify TGC cookie state for debugging"""
        try:
            tgc_cookies = [c for c in self.session.cookies.jar if c.name == 'TGC']
            logger.info(f"[TGC-VERIFY{' ' + context if context else ''}] Current jar state: {len(tgc_cookies)} TGC cookies")
            if len(tgc_cookies) > 1:
                logger.warning(f"[TGC-VERIFY{' ' + context if context else ''}] ⚠️ STILL HAVE {len(tgc_cookies)} TGC COOKIES!")
                for i, cookie in enumerate(tgc_cookies):
                    logger.warning(f"[TGC-VERIFY{' ' + context if context else ''}]   TGC {i}: domain={cookie.domain}, path={cookie.path}")
            elif len(tgc_cookies) == 1:
                logger.debug(f"[TGC-VERIFY{' ' + context if context else ''}] ✅ Single TGC cookie (domain={tgc_cookies[0].domain})")
            else:
                logger.debug(f"[TGC-VERIFY{' ' + context if context else ''}] No TGC cookies")
        except Exception as e:
            import traceback
            logger.error(f"[TGC-VERIFY{' ' + context if context else ''}] Verification failed: {e}")
            logger.debug(f"[TRACEBACK] {traceback.format_exc()}")


    def _extract_session_cookies(self) -> List[Dict[str, str]]:
        """Extract session cookies in Playwright-compatible format"""
        playwright_cookies = []

        try:
            for cookie in self.session.cookies.jar:
                # Convert httpx cookie to Playwright format
                playwright_cookie = {
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httpOnly': getattr(cookie, 'http_only', False),
                }

                # Add expiry if present
                if hasattr(cookie, 'expires') and cookie.expires:
                    if isinstance(cookie.expires, (int, float)):
                        playwright_cookie['expires'] = cookie.expires
                    elif hasattr(cookie.expires, 'timestamp'):
                        playwright_cookie['expires'] = cookie.expires.timestamp()

                playwright_cookies.append(playwright_cookie)

            logger.info(f"[COOKIES] Extracted {len(playwright_cookies)} session cookies for browser transfer")
            return playwright_cookies

        except Exception as e:
            import traceback
            logger.error(f"[ERROR] Failed to extract cookies: {e}")
            logger.debug(f"[TRACEBACK] {traceback.format_exc()}")
            return []


    def _get_dynamic_headers(self, request_type: str = 'navigate') -> Dict[str, str]:
        """Generate dynamic headers to avoid bot detection"""
        base_headers = dict(self.session.headers)
        # Add missing critical headers
        base_headers.update({
            'Priority': 'u=0, i',
            'TE': 'trailers',
            'Sec-GPC': '1'  # Global Privacy Control
        })
        # Modify headers based on request type

        if request_type == 'ajax':
            base_headers.update({
                'X-Requested-With': 'XMLHttpRequest',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin'
            })

        elif request_type == 'form':
            base_headers.update({
                'Content-Type': 'application/x-www-form-urlencoded',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1'
            })
        # Add random variations to avoid fingerprinting

        if random.random() < 0.3:  # 30% chance
            base_headers['Cache-Control'] = random.choice(['no-cache', 'max-age=0', 'no-store'])

        return base_headers



    def _log_session_info(self, phase_name: str) -> Dict[str, str]:
        """Helper method to log session cookie information consistently"""

        cookie_dict = dict(self.session.cookies)
        self._log(logging.INFO, f"🔍 [SESSION CHECK] Verifying session continuity at {phase_name}...")

        self._log(logging.INFO, f"🍪 [COOKIES] Current cookie count: {len(cookie_dict)}")
        coesessionid = cookie_dict.get('coesessionid')
        if coesessionid:
            logger.info(f"✅ [SESSION] coesessionid preserved: {coesessionid[:20]}...")

        if not cookie_dict:
            logger.info("ℹ️ [SESSION] No cookies found - this may be expected")
        else:
            logger.info(f"✅ [SESSION] Session active with {len(cookie_dict)} cookies")

        return cookie_dict


    async def _safe_http_request(self, method: str, url: str, operation: str,
                                data: Dict = None, headers: Dict = None) -> Optional[httpx.Response]:
        """Enhanced HTTP request with adaptive retry logic for high server load."""
        await self._smart_delay()

        request_headers = self._get_dynamic_headers('ajax' if 'ajax' in operation.lower() else 'navigate')
        if headers:
            request_headers.update(headers)

        for attempt in range(self.max_retries + 1):
            # --- THIS IS THE FIX ---
            if self.stop_signal and self.stop_signal.is_set():
                logger.info("🛑 [RETRY-LOOP] Stop signal received, halting retries.")
                return None
            # --- END OF FIX ---
            try:
                # On retries, perform a more aggressive cleanup.
                if attempt > 0:
                    delay = (self.retry_backoff ** attempt) * random.uniform(0.5, 1.5)
                    logger.warning(f"[RETRY] Attempt {attempt + 1}/{self.max_retries + 1} for '{operation}' after {delay:.1f}s delay.")
                    # await asyncio.sleep(delay) # Delays are removed for max speed
                    
                    # Proactive Session Reset on Retry
                    logger.info("[SESSION-RESET] Proactively resetting session state for retry.")
                    self._cleanup_tgc_cookies()
                    self.session_established = False

                if method.upper() == 'GET':
                    response = await self.session.get(url, headers=request_headers)
                elif method.upper() == 'POST':
                    response = await self.session.post(url, data=data, headers=request_headers)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")

                # --- Intelligent Error Handling ---
                # 5xx Server Errors: These are temporary server-side issues. Retry is the correct action.
                if response.status_code in [500, 502, 503, 504]:
                    logger.warning(f"[SERVER-ERROR] Received {response.status_code} on '{operation}'. Server is under load. Retrying...")
                    if attempt < self.max_retries:
                        continue # Go to the next iteration of the loop to retry
                    else:
                        logger.error(f"[FATAL] Server error {response.status_code} persisted after {self.max_retries + 1} attempts.")
                        raise PersistentServerException(f"Server failed with {response.status_code} after all retries.")

                # 429 Too Many Requests: We're rate-limited. Back off significantly.
                elif response.status_code == 429:
                    logger.error(f"[RATE-LIMIT] 429 Too Many Requests on '{operation}'. IP may be temporarily blocked.")
                    # await asyncio.sleep(random.uniform(10, 20)) # Apply a long delay even if sleeps are generally off
                    if attempt < self.max_retries:
                        continue
                    else:
                        logger.error(f"[FATAL] Rate-limited even after retries. Signaling to switch proxy.")
                        raise RateLimitException("Rate limit hit after all retries.")
                
                # 403 Forbidden: Fatal error, likely bot detection. Treat as a rate-limit to trigger proxy switch.
                elif response.status_code == 403:
                    logger.error(f"[FATAL] 403 Forbidden on '{operation}'. IP is blocked. Signaling to switch proxy.")
                    raise RateLimitException("Forbidden error (403) received.")
                
                # --- Success or Other Errors ---
                self._preserve_session_cookies()
                
                if await self.detect_and_handle_session_expired(response):
                    logger.warning(f"[SESSION-EXPIRED] Detected during {operation}")
                    return None # Session is dead, no point retrying this request

                # If status is not 200/302 or another expected code, it's an issue but might not be a server error.
                # Let's log it and let the phase-specific logic handle it.
                if response.status_code not in [200, 302]:
                    logger.warning(f"[UNEXPECTED-STATUS] Operation '{operation}' resulted in status {response.status_code}.")

                return response

            except (httpx.TimeoutException, httpx.NetworkError) as e:
                logger.warning(f"[{e.__class__.__name__}] Network issue on '{operation}' (Attempt {attempt + 1}): {e}")
                if attempt >= self.max_retries:
                    logger.error(f"[FATAL] Network issues persisted for '{operation}'.")
                    return None
            except Exception as e:
                logger.error(f"[CRITICAL] Unexpected exception during '{operation}': {e}")
                return None
        
        return None # Should not be reached, but as a fallback



    def _handle_common_error(self, operation: str, error: Exception) -> bool:
        """Enhanced error handling with bot detection awareness"""
        error_msg = str(error).lower()

        # Check if error indicates bot detection
        bot_error_indicators = [
            '403', 'forbidden', 'blocked', 'rate limit',
            'too many requests', 'connection reset', 'timeout'
        ]

        if any(indicator in error_msg for indicator in bot_error_indicators):
            logger.warning(f"[BOT-DETECTED] Possible bot detection in {operation}: {error}")
            # Suggest longer delay
            self.min_request_delay = max(self.min_request_delay, 2.0)
            self.max_request_delay = max(self.max_request_delay, 5.0)
        else:
            logger.error(f"[ERROR] {operation} failed: {error}")

        return False

    async def extract_and_setup_modules(self, response, desired_modules: List[str], is_flexible: bool = False) -> Optional[httpx.Response]:
        """
        Extracts module states and toggles them based on flexible or strict booking logic.
        This is the definitive, corrected version that checks for disabled checkboxes.
        """
        try:
            current_response = response
            original_desired_modules = set(desired_modules) # Use sets for efficient comparison

            # --- START OF THE DEFINITIVE FIX ---

            # Step 1: Get a clean list of all modules available on the page by checking for DISABLED checkboxes.
            initial_soup = BeautifulSoup(current_response.text, 'html.parser')
            
            module_id_map = {
                'reading': 'READING', 'listening': 'LISTENING',
                'writing': 'WRITING', 'speaking': 'SPEAKING'
            }
            
            available_modules_on_page = set()
            all_checkboxes = initial_soup.find_all('input', {'type': 'checkbox', 'name': re.compile(r'modules')})

            for checkbox in all_checkboxes:
                # A module is available ONLY if its checkbox is NOT disabled.
                if not checkbox.has_attr('disabled'):
                    checkbox_id = checkbox.get('id', '').strip()
                    if checkbox_id in module_id_map:
                        available_modules_on_page.add(module_id_map[checkbox_id])

            self._log(logging.INFO, f"[MODULE-CHECK] Available on page: {list(available_modules_on_page)}")
            self._log(logging.INFO, f"[MODULE-CHECK] Desired by user: {list(original_desired_modules)}")

            # Step 2: Apply the correct logic based on the 'is_flexible' flag.
            target_modules_for_this_loop = set()

            if is_flexible:
                # STRICT MODE: ALL desired modules MUST be available.
                if not original_desired_modules.issubset(available_modules_on_page):
                    missing_modules = original_desired_modules - available_modules_on_page
                    self._log(logging.ERROR, f"[MODULE-FAIL-STRICT] Required module(s) {list(missing_modules)} not available. Halting.")
                    return None
                target_modules_for_this_loop = original_desired_modules
            else:
                # NON-FLEXIBLE MODE: AT LEAST ONE desired module must be available.
                intersection = original_desired_modules.intersection(available_modules_on_page)
                if not intersection:
                    self._log(logging.ERROR, f"[MODULE-FAIL] None of the desired modules {list(original_desired_modules)} are available. Halting.")
                    return None
                # If we proceed, we only target the modules that are actually available.
                target_modules_for_this_loop = intersection
                self._log(logging.INFO, f"[MODULE-CONTINUE] At least one desired module found. Attempting to book: {list(target_modules_for_this_loop)}")

            # --- END OF THE DEFINITIVE FIX ---

            for _ in range(5): # Loop to handle multiple toggles
                if self.stop_signal and self.stop_signal.is_set():
                    self._log(logging.INFO, "🛑 [MODULES] Stop signal received, halting.")
                    return None

                soup = BeautifulSoup(current_response.text, 'html.parser')
                current_url = str(current_response.url)
                
                ajax_urls = {}
                scripts = soup.find_all('script', text=re.compile(r'Wicket.Ajax.ajax'))
                for script in scripts:
                    matches = re.findall(r'Wicket\.Ajax\.ajax\((.*?)\);', script.string)
                    for match in matches:
                        try:
                            component_id_match = re.search(r'"c"\s*:\s*"(.*?)"', match)
                            url_match = re.search(r'"u"\s*:\s*"([^"]+)"', match)
                            if component_id_match and url_match:
                                component_id = component_id_match.group(1).strip()
                                relative_url = url_match.group(1)
                                ajax_urls[component_id] = urljoin(current_url, relative_url)
                        except (json.JSONDecodeError, IndexError):
                            continue
                
                self._log(logging.DEBUG, f"[AJAX-PARSE] Dynamically extracted URLs for: {list(ajax_urls.keys())}")

                toggles_needed = []
                current_checked_modules = []
                
                for checkbox in soup.find_all('input', {'type': 'checkbox', 'name': re.compile(r'modules')}):
                    checkbox_id_with_spaces = checkbox.get('id', '')
                    checkbox_id = checkbox_id_with_spaces.strip()
                    
                    if checkbox_id in module_id_map:
                        module_name = module_id_map[checkbox_id]
                        is_checked = checkbox.has_attr('checked')
                        should_be_checked = module_name in target_modules_for_this_loop
                        
                        if is_checked:
                            current_checked_modules.append(module_name)
                        
                        self._log(logging.DEBUG, f"[MODULE] {module_name}: current={is_checked}, desired={should_be_checked}")
                        if is_checked != should_be_checked:
                            if checkbox_id in ajax_urls:
                                toggles_needed.append({
                                    "name": module_name,
                                    "id": checkbox_id_with_spaces,
                                    "url": ajax_urls[checkbox_id]
                                })
                            else:
                                self._log(logging.WARNING, f"[WARN] No AJAX URL found for '{checkbox_id}', cannot toggle.")

                if not toggles_needed:
                    self._log(logging.INFO, "✅ [MODULES] All modules are in the correct state.")
                    self.final_booked_modules = sorted(list(target_modules_for_this_loop)) # Use the final target list
                    self._log(logging.INFO, f"[STATE SAVE] Final booked modules set to: {self.final_booked_modules}")
                    return current_response

                toggle_action = toggles_needed[0]
                self._log(logging.INFO, f"[TOGGLE] Toggling '{toggle_action['name']}' using URL: {toggle_action['url']}")
                
                parsed_url = urlparse(current_url)
                base_file = os.path.basename(parsed_url.path)
                ajax_base_url = f"{base_file}?{parsed_url.query}" if parsed_url.query else base_file

                toggle_headers = {
                    'Wicket-Ajax': 'true',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Referer': current_url,
                    'Wicket-Ajax-BaseURL': ajax_base_url,
                    'Wicket-FocusedElementId': quote(toggle_action['id'])
                }
                
                toggle_response = await self.session.post(
                    toggle_action['url'], headers=toggle_headers, data="", follow_redirects=False
                )
                
                if toggle_response.status_code == 200:
                    self._log(logging.INFO, "✅ [TOGGLE] Received 200 OK. Re-fetching page state to verify change.")
                    if 'coesessionid' in self.session.cookies:
                        del self.session.cookies['coesessionid']
                    current_response = await self._safe_http_request('GET', current_url, 'Re-fetch page state after toggle')
                    if not current_response: return None
                    continue
                
                elif toggle_response.status_code == 302:
                    self._log(logging.WARNING, "[TOGGLE] Received 302 Redirect. Server is forcing a refresh.")
                    redirect_location = toggle_response.headers.get('Location')
                    if not redirect_location:
                        self._log(logging.ERROR, "[ERROR] Toggle returned 302 but no Location header found.")
                        return None
                    full_redirect_url = urljoin(current_url, redirect_location)
                    self._log(logging.INFO, f"[REDIRECT] Following redirect to: {full_redirect_url}")
                    if 'coesessionid' in self.session.cookies: del self.session.cookies['coesessionid']
                    current_response = await self._safe_http_request('GET', full_redirect_url, 'Get updated module page')
                    if not current_response: return None
                    continue
                else:
                    self._log(logging.ERROR, f"[ERROR] Failed to toggle {toggle_action['name']}: Status {toggle_response.status_code}")
                    return None
            
            self._log(logging.ERROR, "[ERROR] Failed to set all module states after multiple attempts.")
            return None

        except Exception as e:
            self._log(logging.ERROR, f"[ERROR] Module setup failed: {e}")
            import traceback
            self._log(logging.DEBUG, traceback.format_exc())
            return None


    def debug_save_page(self, html_content: str, filename_prefix: str):
        """Save current page HTML for debugging"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"debug_{filename_prefix}_{timestamp}.html"

            # Create logs directory if it doesn't exist
            logs_dir = Path("logs")
            logs_dir.mkdir(exist_ok=True)

            filepath = logs_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"[DEBUG] Page saved to: {filepath}")

        except Exception as e:
            logger.warning(f"[WARNING] Could not save debug page: {e}")


    def extract_recaptcha_sitekey(self, html: str) -> Optional[str]:
        """
        Extracts the reCAPTCHA sitekey from page HTML using a multi-strategy approach.
        """
        # Strategy 1: Use BeautifulSoup to find the g-recaptcha div (most reliable)
        try:
            soup = BeautifulSoup(html, 'html.parser')
            recaptcha_div = soup.find('div', class_='g-recaptcha')
            if recaptcha_div and recaptcha_div.get('data-sitekey'):
                sitekey = recaptcha_div['data-sitekey']
                logger.info(f"[SITEKEY] Found sitekey '{sitekey[:10]}...' using BeautifulSoup.")
                return sitekey
        except Exception as e:
            logger.warning(f"[SITEKEY] BeautifulSoup parsing failed: {e}")

        # Strategy 2: Fallback to Regex on the entire HTML (covers keys in JS)
        # Pattern 1: data-sitekey="KEY"
        match = re.search(r'data-sitekey\s*=\s*["\']([^"\']+)["\']', html)
        if match:
            sitekey = match.group(1)
            logger.info(f"[SITEKEY] Found sitekey '{sitekey[:10]}...' using regex (data-sitekey).")
            return sitekey

        # Pattern 2: sitekey: 'KEY' inside a JavaScript block
        match = re.search(r'["\']?sitekey["\']?\s*:\s*["\']([^"\']+)["\']', html)
        if match:
            sitekey = match.group(1)
            logger.info(f"[SITEKEY] Found sitekey '{sitekey[:10]}...' using regex (JS object).")
            return sitekey
            
        # Pattern 3: In the parameters of the recaptcha/api.js script URL
        match = re.search(r'recaptcha/api\.js\?.*render=([\w-]+)', html)
        if match:
            sitekey = match.group(1)
            logger.info(f"[SITEKEY] Found sitekey '{sitekey[:10]}...' using regex (api.js URL).")
            return sitekey

        logger.error("[SITEKEY] Could not find reCAPTCHA sitekey on the page.")
        return None

    async def _check_and_solve_captcha_if_present(self, response: httpx.Response) -> Optional[str]:
        """
        Checks a response for a reCAPTCHA, solves it if found (v2 or v3), and returns the token.
        """
        self._log(logging.INFO, "[CAPTCHA-CHECK] Checking for reCAPTCHA on current page...")
        sitekey = self.extract_recaptcha_sitekey(response.text)

        if not sitekey:
            self._log(logging.INFO, "[CAPTCHA-CHECK] No reCAPTCHA sitekey found.")
            return None

        if not self.captcha_solver:
            self._log(logging.ERROR, "[CAPTCHA-CHECK] Sitekey found, but CAPTCHA solver is not initialized (missing API key).")
            return None
        
        try:
            # --- MODIFICATION ---
            # We are now explicitly telling the solver it's an invisible reCAPTCHA,
            # bypassing the previous, unreliable detection logic.
            self._log(logging.INFO, "[CAPTCHA-CHECK] Assuming invisible reCAPTCHA v2 based on website behavior.")
            token = await asyncio.to_thread(
                self.captcha_solver.solve_recaptcha,
                sitekey,
                str(response.url),
                action=self.recaptcha_v3_action,
                is_invisible=True
            )
            # --- END MODIFICATION ---

            if token:
                self._log(logging.INFO, "[CAPTCHA-CHECK] ✅ Successfully obtained CAPTCHA token.")
                return token
            else:
                self._log(logging.ERROR, "[CAPTCHA-CHECK] ❌ Solver failed to return a token.")
                return None
        except Exception as e:
            self._log(logging.ERROR, f"[CAPTCHA-CHECK] ❌ An exception occurred during solving: {e}")
            return None

    async def extract_and_call_ajax_continue(self, page_response, current_url: str, page_type: str = "continue") -> Optional[httpx.Response]:
        """
        Extract the navSection-nextLink AJAX URL from page scripts and call it directly.
        This is more efficient than simulating button clicks.
        """
        try:
            soup = BeautifulSoup(page_response.text, 'html.parser')
            
            # Find all script tags
            scripts = soup.find_all('script', type='text/javascript')
            ajax_url = None
            
            for script in scripts:
                script_text = script.get_text() if script else ""
                
                # Look for Wicket.Ajax.ajax calls in the script
                if 'Wicket.Ajax.ajax' in script_text:
                    # Extract navSection-nextLink URL using regex
                    import re
                    # Pattern to match navSection-nextLink URLs
                    pattern = r'Wicket\.Ajax\.ajax\(\{"u":"([^"]*navSection-nextLink[^"]*)"'
                    matches = re.findall(pattern, script_text)
                    
                    if matches:
                        for match in matches:
                            # Found the navSection-nextLink URL
                            relative_url = match
                            # Clean up the URL (remove ./ prefix if present)
                            if relative_url.startswith('./'):
                                relative_url = relative_url[2:]
                            
                            # Construct full URL
                            ajax_url = urljoin(current_url, relative_url)
                            logger.info(f"[AJAX-EXTRACT] Found navSection-nextLink: {ajax_url}")
                            break
                    
                    if ajax_url:
                        break
            
            if not ajax_url:
                logger.warning(f"[AJAX-EXTRACT] No navSection-nextLink found on {page_type} page")
                return None
            
            # Add timestamp to the URL (as seen in network logs)
            import time
            timestamp = int(time.time() * 1000)
            if '?' in ajax_url:
                ajax_url += f"&_={timestamp}"
            else:
                ajax_url += f"?_={timestamp}"
            
            # Add URL validation
            try:
                from urllib.parse import urlparse
                parsed = urlparse(ajax_url)
                if not parsed.scheme or not parsed.netloc:
                    logger.error(f"[URL-ERROR] Constructed invalid URL: {ajax_url}")
                    return None
            except Exception as e:
                logger.error(f"[URL-ERROR] URL validation failed: {e}")
                return None
            
            logger.info(f"[AJAX-CALL] Sending GET request to: {ajax_url}")
            
            # Send the AJAX request with proper headers
            ajax_headers = {
                'Accept': 'text/html, */*; q=0.01',
                'Accept-Language': 'en-US,en;q=0.9',
                'X-Requested-With': 'XMLHttpRequest',
                'Referer': current_url,
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin'
            }
            
            # Make the GET request WITHOUT auto-following redirects
            response = await self.session.get(
                ajax_url,
                headers=ajax_headers,
                follow_redirects=False  # Don't auto-follow redirects
            )
            
            # Handle both 200 with ajax-location AND 302 redirects
            if response.status_code == 200:
                # Check for ajax-location header
                ajax_location = response.headers.get('ajax-location')
                if ajax_location:
                    logger.info(f"[AJAX-LOCATION] Found ajax-location header: {ajax_location}")
                    
                    # Resolve the ajax-location URL
                    if ajax_location.startswith('../'):
                        # Handle relative paths like ../psp-selection?1
                        base_url = current_url.rsplit('/', 1)[0]
                        next_url = urljoin(base_url + '/', ajax_location)
                    elif ajax_location.startswith('./'):
                        next_url = urljoin(current_url, ajax_location[2:])
                    elif ajax_location.startswith('/'):
                        from urllib.parse import urlparse
                        parsed = urlparse(current_url)
                        next_url = f"{parsed.scheme}://{parsed.netloc}{ajax_location}"
                    else:
                        next_url = urljoin(current_url, ajax_location)
                    
                    logger.info(f"[AJAX-NAVIGATE] Navigating to: {next_url}")
                    
                    # Navigate to the next page
                    nav_headers = {
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Referer': current_url,
                        'Sec-Fetch-Dest': 'document',
                        'Sec-Fetch-Mode': 'navigate',
                        'Sec-Fetch-Site': 'same-origin',
                        'Upgrade-Insecure-Requests': '1'
                    }
                    
                    next_response = await self.session.get(next_url, headers=nav_headers)
                    return next_response
                else:
                    logger.warning(f"[AJAX-RESPONSE] No ajax-location header in response")
                    return response
                    
            elif response.status_code == 302:
                # Handle 302 redirect response
                location_header = response.headers.get('Location')
                if location_header:
                    logger.info(f"[AJAX-302] Got 302 redirect to: {location_header}")
                    
                    # Resolve the redirect URL
                    if location_header.startswith('../'):
                        base_url = current_url.rsplit('/', 1)[0]
                        next_url = urljoin(base_url + '/', location_header)
                    elif location_header.startswith('./'):
                        next_url = urljoin(current_url, location_header[2:])
                    elif location_header.startswith('/'):
                        from urllib.parse import urlparse
                        parsed = urlparse(current_url)
                        next_url = f"{parsed.scheme}://{parsed.netloc}{location_header}"
                    else:
                        next_url = urljoin(current_url, location_header)
                    
                    logger.info(f"[AJAX-REDIRECT] Following 302 redirect to: {next_url}")
                    
                    # Follow the redirect with navigation headers
                    nav_headers = {
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Referer': current_url,
                        'Sec-Fetch-Dest': 'document',
                        'Sec-Fetch-Mode': 'navigate',
                        'Sec-Fetch-Site': 'same-origin',
                        'Upgrade-Insecure-Requests': '1'
                    }
                    
                    next_response = await self.session.get(next_url, headers=nav_headers)
                    return next_response
                else:
                    logger.error("[AJAX-302] 302 response but no Location header found")
                    return None
            else:
                logger.error(f"[AJAX-ERROR] Request failed with unexpected status: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"[ERROR] Failed to extract and call AJAX URL: {e}")
            return None

    async def phase_1_monitor_exam_url(self, exam_url: str, check_interval: float = 0.1) -> Optional[httpx.Response]:

        """Phase 1: Enhanced monitoring. Returns the response object on success, None on failure."""

        self._log(logging.INFO, ">>> Phase 1: Monitor exam URL for SELECT MODULES button")

        # Clean TGC cookies at phase start
        # self._cleanup_tgc_cookies()  # COMMENTED OUT - preserve session state

        self._log(logging.INFO, f"[MONITOR] Starting to monitor: {exam_url}")

        # === SESSION CONTINUITY CHECK ===

        cookie_dict = self._log_session_info("Phase 1")
        if not cookie_dict:
            self._log(logging.INFO, "ℹ️ [SESSION] This is expected for initial request")

        self.current_exam_url = exam_url
        start_time = time.time()
        check_count = 0
        consecutive_failures = 0
        # Anti-bot detection: Vary check intervals
        base_interval = check_interval
        
        while True:
            # --- THIS IS THE FIX ---
            if self.stop_signal and self.stop_signal.is_set():
                self._log(logging.INFO, "🛑 [MONITOR] Stop signal received, halting monitoring.")
                return None # Return None to indicate failure/stop signal received
            # --- END OF FIX ---

            try:

                check_count += 1

                # Dynamic interval adjustment to avoid pattern detection
                if check_count > 100:
                    # Slow down after many attempts to avoid detection
                    dynamic_interval = base_interval * random.uniform(2.0, 4.0)
                elif consecutive_failures > 3:
                    # Back off on consecutive failures
                    dynamic_interval = base_interval * random.uniform(5.0, 10.0)
                else:
                    # Normal operation with slight randomization
                    dynamic_interval = base_interval * random.uniform(0.8, 1.5)

                # Access the exam page with enhanced session management
                response = await self._safe_http_request('GET', exam_url, 'Exam page monitoring')

                if not response:
                    consecutive_failures += 1
                    logger.warning(f"[WARNING] Failed to access exam page (failure {consecutive_failures}), retrying...")

                    # Progressive backoff on failures
                    failure_delay = min(dynamic_interval * (2 ** consecutive_failures), 30.0)
                    # await asyncio.sleep(failure_delay)  # Commented out for maximum speed

                    continue



                # Reset failure counter on success

                consecutive_failures = 0



                # Check for window['examButtonLink'] pattern
                exam_button_link_match = re.search(r"window\['examButtonLink'\]\s*=\s*['\"]([^'\"]+)['\"]\s*;", response.text)
                
                if exam_button_link_match and exam_button_link_match.group(1).strip():
                    # Extract the URL from the match
                    booking_url = exam_button_link_match.group(1).strip()
                    elapsed = time.time() - start_time
                    logger.info(f"[SLOT-DETECTED] Exam button link found after {elapsed:.1f}s ({check_count} checks)!")
                    logger.info(f"[URL-FOUND] Booking URL: {booking_url}")

                    # Store the response for next phase
                    self.current_page_response = response
                    return response
                
                # Fallback to the original SELECT MODULES check
                elif 'SELECT MODULES' in response.text.upper():
                    elapsed = time.time() - start_time
                    logger.info(f"[SLOT-DETECTED] SELECT MODULES button found after {elapsed:.1f}s ({check_count} checks)!")

                    # Store the response for next phase
                    self.current_page_response = response
                    return response



                # Enhanced logging with session status

                if check_count % 25 == 0:  # More frequent updates

                    elapsed = time.time() - start_time

                    avg_interval = elapsed / check_count

                    logger.info(f"[MONITOR] Check {check_count}: {elapsed:.1f}s elapsed, avg {avg_interval:.2f}s/check")

                    logger.info(f"[STATUS] Waiting for SELECT MODULES button... (session: {len(dict(self.session.cookies))} cookies)")



                # Continue without delay for maximum speed monitoring

                # --- ADD THIS BLOCK ---
                # Apply a human-like delay between checks
                human_like_delay = random.uniform(2.0, 3.0)
                await asyncio.sleep(human_like_delay)
                # --- END OF BLOCK ---

            except Exception as e:

                consecutive_failures += 1

                self._handle_common_error("Monitor loop", e)

                # await asyncio.sleep(dynamic_interval * 2)  # Extra delay on exceptions - Commented out for maximum speed

    # --- UPDATED METHOD ---
    async def phase_2_breakthrough_module_page(self, initial_modules_page_url: str) -> Optional[httpx.Response]:
        """Controlled approach to handle server errors with exponential backoff"""
        logger.info("[BREAKTHROUGH] Initiating controlled module page access.")
        
        # Check if we have a booking URL from the exam button link
        booking_url = None
        if hasattr(self, 'current_page_response') and self.current_page_response:
            exam_button_link_match = re.search(r"window\['examButtonLink'\]\s*=\s*['\"]([^'\"]+)['\"]\s*;", 
                                              self.current_page_response.text)
            if exam_button_link_match and exam_button_link_match.group(1).strip():
                booking_url = exam_button_link_match.group(1).strip()
                logger.info(f"[BREAKTHROUGH] Using exam button link: {booking_url}")
                # Use the extracted booking URL instead of the initial URL
                initial_modules_page_url = booking_url
        
        max_attempts = 5  # Limit attempts
        for attempt in range(max_attempts):
            if self.stop_signal and self.stop_signal.is_set():
                logger.info("🛑 [BREAKTHROUGH] Stop signal received.")
                return None
            
            try:
                # DON'T cleanup cookies here - preserve session state
                # self._cleanup_tgc_cookies()  # REMOVE THIS
                
                # Add exponential backoff with jitter
                if attempt > 0:
                    wait_time = min(30, (2 ** attempt) + random.uniform(0, 2))
                    logger.info(f"⏳ [BREAKTHROUGH] Waiting {wait_time:.1f}s before attempt {attempt + 1}")
                    await asyncio.sleep(wait_time)
                
                headers = self._get_dynamic_headers('navigate')
                response = await self.session.get(initial_modules_page_url, headers=headers)
                
                if response.status_code in [200, 302]:
                    logger.info(f"✅ [BREAKTHROUGH] Success on attempt {attempt + 1}")
                    self.current_page_response = response
                    return response
                
                elif response.status_code == 429:
                    logger.error(f"⚠️ [BREAKTHROUGH] Rate limited (429). Stopping.")
                    raise RateLimitException("Rate limited")
                
                elif response.status_code >= 500:
                    logger.warning(f"⚠️ [BREAKTHROUGH] Server error {response.status_code}, will retry with backoff")
                    continue
                
                else:
                    logger.warning(f"❓ [BREAKTHROUGH] Unexpected status {response.status_code}")
                    
            except RateLimitException:
                raise
            except Exception as e:
                logger.error(f"❌ [BREAKTHROUGH] Error on attempt {attempt + 1}: {e}")
        
        logger.error(f"❌ [BREAKTHROUGH] Failed after {max_attempts} attempts")
        raise PersistentServerException(f"Breakthrough failed after {max_attempts} attempts with server errors.")

    async def phase_2_module_selection_and_booking(self, modules: List[str], is_flexible: bool = False, initial_response: httpx.Response = None) -> bool:
        """Phase 2: Module Selection and Booking Initiation - FINAL FIXED VERSION"""
        self._log(logging.INFO, ">>> Phase 2: Module Selection and Booking Initiation")
        # self._cleanup_tgc_cookies()  # COMMENTED OUT - preserve session state
        self._log_session_info("Phase 2")

        try:
            # If an initial_response is passed (from the breakthrough phase), use it.
            if initial_response:
                self.current_page_response = initial_response
            
            if not self.current_page_response:
                self._log(logging.ERROR, "[ERROR] Phase 2 cannot start without the module page content.")
                return False

            # The breakthrough function has already landed us on the module page.
            # We no longer need to find and click the 'SELECT MODULES' link.
            # We can proceed directly to setting up the modules.
            response = self.current_page_response
            self._log(logging.INFO, f"[MODULES] Successfully loaded module page: {str(response.url)}")
            
            # Step 1: Set up the module checkboxes
            self._log(logging.INFO, "[MODULES] Setting up module selection...")
            updated_response = await self.extract_and_setup_modules(response, modules, is_flexible)

            if not updated_response:
                self._log(logging.ERROR, "[ERROR] Module setup failed.")
                return False
            
            # Use the new, updated response for all subsequent actions
            response = updated_response 
            self._log(logging.INFO, "[MODULES] ✅ Module selection completed and page state is updated.")
            
            # Step 2: Extract and call the AJAX 'continue' URL to move to the next page
            self._log(logging.INFO, "[CONTINUE] Extracting and calling 'continue' link from module page...")
            ajax_response = await self.extract_and_call_ajax_continue(response, str(response.url), "options")

            if ajax_response:
                response = ajax_response
                self._log(logging.INFO, f"[SUCCESS] Navigated to participant selection page: {str(response.url)}")
            else:
                self._log(logging.ERROR, "[ERROR] Failed to navigate from module page to participant selection.")
                return False

            # Step 3: Find and click the "BOOK FOR MYSELF" button
            self._log(logging.INFO, "[BOOK] Searching for 'BOOK FOR MYSELF' button...")
            soup = BeautifulSoup(response.text, 'html.parser')
            self.debug_save_page(response.text, "participant_selection_page")

            # Improved logic to find the correct Wicket AJAX URL for the booking button
            all_scripts = soup.find_all("script", type="text/javascript")
            ajax_url = None
            for script in all_scripts:
                if script.string and 'bookcontractor' in script.string.lower():
                    matches = re.findall(r'"u"\s*:\s*"([^"]+)"', script.string)
                    for url in matches:
                        if 'bookcontractor' in url.lower() and 'footer' not in url.lower():
                            ajax_url = urljoin(str(response.url), url.replace('./', ''))
                            self._log(logging.INFO, f"[SUCCESS] Found valid booking URL in script: {ajax_url}")
                            break
                    if ajax_url:
                        break
            
            if not ajax_url:
                self._log(logging.ERROR, "[ERROR] Could not determine correct Wicket AJAX URL for 'BOOK FOR MYSELF'")
                return False
            
            # Step 4: Make a regular GET request to the booking link to trigger the login redirect
            self._log(logging.INFO, f"📍 [REQUEST] Making regular GET request to: {ajax_url}")
            nav_headers = { 'Referer': str(response.url) }
            book_response = await self.session.get(ajax_url, headers=nav_headers, follow_redirects=False)
            
            self._log(logging.INFO, f"📥 [RESPONSE] Status: {book_response.status_code}")
            if book_response.status_code == 302:
                redirect_location = book_response.headers.get('Location', '')
                self._log(logging.INFO, f"🔄 [REDIRECT] Got 302 redirect to: {redirect_location}")

                if 'login.goethe.de' in redirect_location or 'cas/login' in redirect_location:
                    self._log(logging.INFO, "🎉 [SUCCESS] Redirected to login page!")
                    self.login_redirect_url = redirect_location
                    self.login_trigger_response = book_response
                    from urllib.parse import urlparse, parse_qs
                    self.booking_service_url = parse_qs(urlparse(redirect_location).query).get('service', [''])[0]
                    self._log(logging.INFO, f"📌 [SERVICE] Captured service URL: {self.booking_service_url}")
                    return True
            
            self._log(logging.ERROR, "[ERROR] Did not receive the expected redirect to the login page.")
            return False

        except Exception as e:
            self._log(logging.ERROR, f"[ERROR] Phase 2 failed with an unexpected error: {e}")
            import traceback
            self._log(logging.DEBUG, traceback.format_exc())
            return False

        except Exception as e:
            return self._handle_common_error("Phase 2", e)


    async def phase_3_login_when_required(self, email: str, password: str) -> bool:
        """Phase 3: Handle login when prompted (after clicking BOOK FOR MYSELF) - Enhanced Version"""

        logger.info(">>> Phase 3: Login When Required")

        # Clean TGC cookies at phase start
        self._cleanup_tgc_cookies()
        try:
            # Check if we have a captured redirect URL from the "BOOK FOR MYSELF" request
            if hasattr(self, 'login_redirect_url') and self.login_redirect_url:
                logger.info(f"🔐 [LOGIN] Following captured redirect to: {self.login_redirect_url}")

                # Add delay to avoid bot detection
                # await asyncio.sleep(random.uniform(2.0, 4.0))  # Commented out for maximum speed
                # Access the login page
                login_response = await self.session.get(
                    self.login_redirect_url,
                    headers={
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Referer': 'https://www.goethe.de/',  # Coming from goethe.de
                        'Sec-Fetch-Dest': 'document',
                        'Sec-Fetch-Mode': 'navigate',
                        'Sec-Fetch-Site': 'same-site'
                    }
                )

                if login_response.status_code == 200:
                    response = login_response
                    current_url = str(login_response.url)
                    logger.info("✅ [SUCCESS] Reached CAS login page via captured redirect")
                else:
                    logger.error(f"❌ [ERROR] Failed to follow captured redirect: {login_response.status_code}")
                    # Fall back to the trigger response
                    response = self.login_trigger_response
                    current_url = str(response.url)
            else:
                # Use the original trigger response
                response = self.login_trigger_response
                current_url = str(response.url)

            logger.info(f"[LOGIN] Checking for login requirement from URL: {current_url}")

            # Force login if indicators found, even if URL isn't login.goethe.de
            response_text = response.text.lower()
            login_indicators = ['login', 'authentication', 'credentials', 'sign in', 'cas/login']

            if any(indicator in response_text for indicator in login_indicators):
                logger.info("[LOGIN] Login indicators found - forcing login handling")

                # Parse login form if embedded
                soup = BeautifulSoup(response.text, 'html.parser')
                login_form = soup.find('form', action=lambda x: x and ('login' in x.lower() or 'cas' in x.lower()))

                if login_form:
                    form_action = login_form.get('action', '')
                    login_url = urljoin(current_url, form_action) if form_action else current_url
                    logger.info(f"📋 [FORM] Found embedded login form with action: {login_url}")
                    # Collect form data
                    login_data = {}
                    for input_elem in login_form.find_all('input'):
                        name = input_elem.get('name')
                        value = input_elem.get('value', '')
                        if name:
                            login_data[name] = value



                    # Set credentials
                    login_data['username'] = email
                    login_data['password'] = password
                    if '_eventId' not in login_data:

                        login_data['_eventId'] = 'submit'

                    logger.info(f"📤 [LOGIN] Submitting embedded login form to: {login_url}")
                    form_headers = {

                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',

                        'Accept-Language': 'en-US,en;q=0.9',

                        'Accept-Encoding': 'gzip, deflate, br',

                        'Cache-Control': 'max-age=0',

                        'Connection': 'keep-alive',

                        'Content-Type': 'application/x-www-form-urlencoded',

                        'Origin': urljoin(login_url, '/'),

                        'Referer': current_url

                    }
                    login_response = await self._safe_http_request(
                        'POST', login_url, 'Embedded login form submission',
                        data=login_data, headers=form_headers
                    )

                    if login_response.status_code in [200, 302]:
                        logger.info(f"✅ [LOGIN] Login form submission successful: {login_response.status_code}")
                        self.post_login_response = login_response
                        return True
                    else:
                        logger.error(f"❌ [ERROR] Login form submission failed: {login_response.status_code}")

                        return False

                else:
                    # If no form, use the captured service URL from booking flow
                    logger.info("🔍 [ENHANCED] Using captured service URL for CAS login...")

                    # Use the service URL captured during the "BOOK FOR MYSELF" redirect
                    service_param = getattr(self, 'booking_service_url', None)

                    if not service_param:
                        logger.warning("⚠️ [WARNING] No captured service URL - attempting to extract from current context")

                        # Try to extract service parameter from current context

                        if 'coeintid=' in current_url:
                            coeintid = current_url.split('coeintid=')[1].split('&')[0].split('?')[0]
                            service_param = f"https://www.goethe.de/coe/cas?coeintid={coeintid}"

                        elif hasattr(self, 'booking_coeintid') and self.booking_coeintid:
                            service_param = f"https://www.goethe.de/coe/cas?coeintid={self.booking_coeintid}"
                        elif hasattr(self, 'coesessionid') and self.coesessionid:
                            service_param = f"https://www.goethe.de/coe/cas?coesessionid={self.coesessionid}"

                        else:
                            service_param = "https://www.goethe.de/coe/cas"
                            logger.error("❌ [CRITICAL] No booking context available - using generic service URL")

                    logger.info(f"🎯 [SERVICE] Using service URL: {service_param}")

                    # Construct the proper CAS login URL with the captured service parameter

                    from urllib.parse import quote

                    login_url = f"https://login.goethe.de/cas/login?service={quote(service_param, safe=':/?&=')}&renew=true&locale=en"

                    logger.info(f"🔐 [LOGIN] CAS login URL: {login_url}")

                    # Enhanced browser-like navigation headers to avoid bot detection

                    human_delay = random.uniform(2.5, 5.0)

                    logger.info(f"[ANTI-BOT] Applying human-like delay of {human_delay:.2f}s before login redirect.")

                    # await asyncio.sleep(human_delay)  # Commented out for maximum speed

                    login_get_headers = {

                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',

                        'Accept-Language': 'en-US,en;q=0.9',

                        'Accept-Encoding': 'gzip, deflate, br',

                        'Referer': str(response.url),

                        'User-Agent': self.session.headers['User-Agent'],

                        'Connection': 'keep-alive',

                        'Upgrade-Insecure-Requests': '1',

                        'Sec-Fetch-Dest': 'document',

                        'Sec-Fetch-Mode': 'navigate',

                        'Sec-Fetch-Site': 'same-site',

                        'Cache-Control': 'max-age=0'

                    }



                    logger.info("🔧 [HEADERS] Applying enhanced browser-like headers for CAS login GET request...")



                    login_response = await self.session.get(login_url, headers=login_get_headers)

                    if login_response and login_response.status_code == 200:

                        logger.info("✅ [SUCCESS] Reached CAS login page with proper service URL")

                        response = login_response

                        current_url = str(login_response.url)

                    else:

                        logger.error(f"❌ [ERROR] Failed to reach CAS login")

                        return False



            # Check if we're now on a login page (either originally or after redirection)

            if 'login.goethe.de' in current_url or 'cas/login' in current_url:

                logger.info("[LOGIN] On CAS login page - proceeding with login form submission...")



                # Parse the CAS login form

                soup = BeautifulSoup(response.text, 'html.parser')



                # Find the login form

                login_form = soup.find('form', {'id': 'fm1'}) or soup.find('form', action=lambda x: x and 'login' in x)



                if not login_form:

                    logger.error("[ERROR] Could not find login form on CAS page")

                    return False



                # Extract form action

                form_action = login_form.get('action', '/cas/login')

                if not form_action.startswith('http'):

                    login_url = urljoin(current_url, form_action)

                else:

                    login_url = form_action



                logger.info(f"[LOGIN] Found CAS login form with action: {login_url}")



                # Collect hidden form fields

                login_data = {}

                for input_elem in login_form.find_all('input'):

                    name = input_elem.get('name')

                    value = input_elem.get('value', '')

                    input_type = input_elem.get('type', 'text')



                    if name and input_type in ['hidden', 'text', 'password', 'email']:

                        login_data[name] = value



                # Set login credentials

                login_data['username'] = email

                login_data['password'] = password



                # Ensure required CAS fields

                if '_eventId' not in login_data:

                    login_data['_eventId'] = 'submit'

                if 'submit' not in login_data:

                    login_data['submit'] = 'Login'



                logger.info(f"📤 [LOGIN] Submitting CAS login form...")

                # =================== ADD THIS FIX ===================

                # The successful login POST will trigger a redirect chain that issues a NEW,

                # authenticated coesessionid. To prevent a conflict with the old,

                # unauthenticated one, we clear it from the cookie jar first.

                if 'coesessionid' in self.session.cookies:

                    old_cookie = self.session.cookies.get('coesessionid', 'N/A')

                    del self.session.cookies['coesessionid']

                    logger.info(f"[COOKIE-CLEAR] Cleared pre-login coesessionid ({old_cookie[:10]}...) to prevent conflict.")

                # =======================================================



                # Submit login form with enhanced session management

                cas_form_headers = {

                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',

                    'Accept-Language': 'en-US,en;q=0.9',

                    'Accept-Encoding': 'gzip, deflate, br',

                    'Cache-Control': 'max-age=0',

                    'Connection': 'keep-alive',

                    'Content-Type': 'application/x-www-form-urlencoded',

                    'Origin': 'https://login.goethe.de',

                    'Referer': current_url

                }

                login_response = await self._safe_http_request(

                    'POST', login_url, 'CAS login form submission',

                    data=login_data, headers=cas_form_headers

                )



                logger.info(f"📥 [LOGIN] Login response: {login_response.status_code}")

                logger.info(f"📥 [LOGIN] Final URL: {str(login_response.url)}")



                # Check if login was successful

                if login_response:

                    response_text = login_response.text.lower()



                    # Check for success indicators

                    if ('goethe.de/coe' in str(login_response.url) or

                        'successfully' in response_text or

                        'success' in response_text):

                        logger.info("✅ [SUCCESS] Login appears successful")

                        self.post_login_response = login_response

                        return True



                    elif 'error' in response_text or 'invalid' in response_text:

                        logger.error("❌ [ERROR] Login failed - invalid credentials")

                        return False

                    else:

                        logger.info("✅ [LOGIN] Login form submitted successfully")

                        self.post_login_response = login_response

                        return True

                else:

                    logger.error(f"❌ [ERROR] Login submission failed: {login_response.status_code}")

                    return False

            else:

                logger.info("⏭️ [SKIP] No login required - proceeding to next phase")

                self.post_login_response = response

                return True



        except Exception as e:

            logger.error(f"❌ [ERROR] Phase 3 failed: {e}")

            return False



    async def detect_and_handle_session_expired(self, response) -> bool:

        """Detect session expiry and bot detection indicators"""

        response_text = response.text.lower()



        # Session expiry indicators

        session_expired_indicators = [

            'session expired', 'session has expired', 'sitzung abgelaufen',

            'session timeout', 'session invalid', 'session not found',

            'please start again', 'bitte erneut starten',

            'your session has timed out', 'session wurde beendet'

        ]



        # Bot detection indicators

        bot_detection_indicators = [

            'access denied', 'blocked', 'forbidden', 'rate limit',

            'too many requests', 'suspicious activity', 'automated traffic',

            'captcha', 'verification required', 'security check',

            'unusual traffic', 'bot detected', 'please verify'

        ]



        # Check for session expiry

        if any(indicator in response_text for indicator in session_expired_indicators):

            logger.error("🚨 [SESSION-EXPIRED] Session expiry detected!")

            logger.error(f"🚨 [URL] Current URL: {str(response.url)}")

            return True



        # Check for bot detection

        if any(indicator in response_text for indicator in bot_detection_indicators):

            logger.warning("🤖 [BOT-DETECTED] Possible bot detection indicators found")

            logger.warning(f"🤖 [URL] Current URL: {str(response.url)}")

            # Return False to allow retry logic to handle this

            return False



        # Check response status for additional indicators

        if response.status_code == 429:  # Too Many Requests

            logger.warning("🚨 [RATE-LIMIT] Rate limit detected (429)")

            return False



        return False  # No critical issues detected



    async def phase_3_4_oska_acc_page(self) -> bool:

        """Phase 3.4: Handle OSKA-ACC page if it appears after login"""

        logger.info(">>> Phase 3.4: Handle OSKA-ACC Page (if present)")

        # THE FIX: Add comprehensive cookie cleanup here
        self._cleanup_tgc_cookies()

        try:

            # Use the post-login response

            if not hasattr(self, 'post_login_response') or not self.post_login_response:

                logger.error("[ERROR] No post-login response available")

                return False



            response = self.post_login_response

            current_url = str(response.url)



            # Check if we're on the OSKA-ACC page

            if 'oska-acc' not in current_url.lower():

                logger.info("[SKIP] No OSKA-ACC page detected, proceeding to voucher page")

                return True



            logger.info(f"[OSKA-ACC] Detected OSKA-ACC page: {current_url}")



            # Save page for debugging

            self.debug_save_page(response.text, "oska_acc_page")



            # Look for continue button using similar logic as other phases

            soup = BeautifulSoup(response.text, 'html.parser')

            continue_link = None

            continue_button = None



            logger.info("[CONTINUE] Searching for continue button on OSKA-ACC page...")



            # Strategy 1: Look for nextLink pattern in href

            all_links = soup.find_all('a', href=True)

            for link in all_links:

                link_href = link.get('href', '')

                if 'nextLink' in link_href:

                    continue_link = urljoin(str(response.url), link_href)

                    logger.info(f"[FOUND] Continue nextLink: {continue_link}")

                    break



            # Strategy 2: Look for buttons with continue-related text

            if not continue_link:

                all_buttons = soup.find_all('button')

                for button in all_buttons:

                    button_text = button.get_text(strip=True).upper()

                    if any(word in button_text for word in ['CONTINUE', 'NEXT', 'PROCEED', 'WEITER']):

                        continue_button = button

                        logger.info(f"[FOUND] Continue button: {button.get('id', '')} - '{button_text}'")

                        break



            # Strategy 3: Look for regular links with continue-related text

            if not continue_link and not continue_button:

                for link in all_links:

                    link_text = link.get_text(strip=True).upper()

                    if any(word in link_text for word in ['CONTINUE', 'NEXT', 'PROCEED', 'WEITER']):

                        continue_link = urljoin(str(response.url), link['href'])

                        logger.info(f"[FOUND] Continue link: {continue_link}")

                        break



            # Execute continue action with verification and fallback
            next_response = None
            if continue_button:
                logger.info("[CONTINUE] Clicking button on OSKA-ACC page...")
                next_response = await self.click_wicket_button(continue_button, str(response.url), "continue")
            elif continue_link:
                logger.info(f"[CONTINUE] Using link: {continue_link}")
                next_response = await self._safe_http_request('GET', continue_link, 'Continue from OSKA-ACC page')
            else:
                logger.error("[ERROR] Could not find continue mechanism on OSKA-ACC page")
                return False

            if not next_response:
                logger.error("[ERROR] Failed to continue from OSKA-ACC page")
                return False
            
            # Verification and Fallback Logic
            final_url = str(next_response.url)
            if 'voucher' not in final_url.lower() and 'psp' not in final_url.lower():
                logger.warning(f"[OSKA-ACC] Navigation resulted in an unexpected page: {final_url}. Attempting fallback.")
                
                # Construct fallback URL (e.g., from /oska-acc?8 to /voucher?9)
                import re
                page_num_match = re.search(r'\?(\d+)', current_url)
                next_page_num = int(page_num_match.group(1)) + 1 if page_num_match else 9
                
                fallback_url = current_url.replace('/oska-acc', '/voucher').split('?')[0] + f'?{next_page_num}'
                logger.info(f"[OSKA-ACC] Fallback: Navigating directly to constructed voucher URL: {fallback_url}")
                
                # Clean cookies again before fallback attempt
                self._cleanup_tgc_cookies()
                
                next_response = await self._safe_http_request('GET', fallback_url, 'OSKA-ACC fallback navigation')
                if not next_response or 'voucher' not in str(next_response.url).lower():
                    logger.error("[ERROR] OSKA-ACC fallback navigation also failed.")
                    self.debug_save_page(next_response.text if next_response else "", "oska_acc_fallback_failed")
                    return False

            # Update the post_login_response for the next phase
            self.post_login_response = next_response
            logger.info(f"[SUCCESS] Continued from OSKA-ACC page to: {str(next_response.url)}")
            return True



        except Exception as e:

            logger.error(f"[ERROR] Phase 3.4 failed: {e}")

            return False

    async def phase_3_5_voucher_payment_page(self) -> bool:

        """Phase 3.5: Handle voucher/payment page after login"""

        logger.info(">>> Phase 3.5: Handle Voucher/Payment Page")

        # Clean TGC cookies at phase start
        self._cleanup_tgc_cookies()

        try:

            # Use the post-login response which should now be the voucher page

            if not hasattr(self, 'post_login_response') or not self.post_login_response:

                logger.error("[ERROR] No post-login response available")

                return False

            response = self.post_login_response

            current_url = str(response.url)



            # =================== ADD THIS FIX ===================

            # Proactively fix any duplicate cookies from the login redirect chain

            self._cleanup_tgc_cookies()

            # ====================================================

            # Check if we're on the voucher page or PSP page (both are valid)

            if 'voucher' not in current_url.lower() and 'psp' not in current_url.lower():

                logger.warning(f"[WARNING] Expected voucher/payment page, got: {current_url}")

                # The improved click_wicket_button should have handled this,

                # but if not, the process should fail gracefully.

                self.debug_save_page(response.text, "unexpected_page_before_voucher")

                logger.error("[ERROR] Did not land on the voucher/payment page after login. Halting.")

                return False



            # Determine which page we're on and log appropriately

            if 'voucher' in current_url.lower():

                logger.info(f"[VOUCHER] On voucher page: {str(response.url)}")

                page_type = "voucher"

            elif 'psp' in current_url.lower():

                logger.info(f"[PSP] Already on PSP page: {str(response.url)}")

                page_type = "psp"

                # If we're already on PSP page, skip to next phase

                self.voucher_continue_response = response

                return True

            else:

                logger.info(f"[PAYMENT] On payment-related page: {str(response.url)}")

                page_type = "payment"



            # Save page for debugging

            self.debug_save_page(response.text, f"{page_type}_page")



            # Look for continue button using similar logic as phase 2

            soup = BeautifulSoup(response.text, 'html.parser')

            continue_link = None

            continue_button = None



            logger.info(f"[CONTINUE] Searching for continue button on {page_type} page...")



            # Strategy 1: Look for navSection-nextLink pattern (prioritize correct URLs, filter out footer)

            all_links = soup.find_all('a', href=True)

            potential_links = []



            for link in all_links:

                link_href = link.get('href', '')



                # Skip footer and unwanted elements

                if any(exclude in link_href.lower() for exclude in ['footer', 'footerelement', 'statussection']):

                    logger.debug(f"[SKIP] Footer/status link: {link_href}")

                    continue



                # Look for nextLink patterns

                if 'nextLink' in link_href:

                    priority = 0

                    full_link = urljoin(str(response.url), link_href)



                    # Prioritize navSection-nextLink (this is the correct pattern)

                    if 'navsection-nextlink' in link_href.lower():

                        priority = 3  # Highest priority

                    elif 'coecontainer-navsection-nextlink' in link_href.lower():

                        priority = 2  # High priority

                    elif 'navsection' in link_href.lower():

                        priority = 1  # Medium priority



                    potential_links.append((priority, full_link, link_href))



            # Sort by priority and use the highest priority link

            if potential_links:

                potential_links.sort(key=lambda x: x[0], reverse=True)

                continue_link = potential_links[0][1]

                logger.info(f"[FOUND] Continue nextLink (priority {potential_links[0][0]}): {potential_links[0][2]}")

                logger.info(f"[FOUND] Full URL: {continue_link}")



            # Strategy 2: Look for buttons with continue-related text

            if not continue_link:

                all_buttons = soup.find_all('button')

                for button in all_buttons:

                    button_text = button.get_text(strip=True).upper()

                    if any(word in button_text for word in ['CONTINUE', 'NEXT', 'PROCEED', 'WEITER']):

                        continue_button = button

                        logger.info(f"[FOUND] Continue button: {button.get('id', '')} - '{button_text}'")

                        break



            # Execute continue action using direct AJAX call
            logger.info(f"[CONTINUE] Extracting navSection-nextLink from {page_type} page...")

            # Use the new AJAX extraction method
            ajax_response = await self.extract_and_call_ajax_continue(response, str(response.url), page_type)

            if ajax_response:
                response = ajax_response
                logger.info(f"[SUCCESS] Navigated from {page_type} to: {str(response.url)}")
            else:
                logger.error(f"[ERROR] Failed to navigate from {page_type} page")
                return False




            # Store response for next phase

            self.voucher_continue_response = response

            logger.info(f"[SUCCESS] Continued from {page_type} page to: {str(response.url)}")

            return True



        except Exception as e:

            logger.error(f"[ERROR] Phase 3.5 failed: {e}")

            return False



    async def phase_4_psp_selection_page(self) -> bool:

        """Phase 4: Handle PSP (Payment Service Provider) selection page"""

        logger.info(">>> Phase 4: Handle PSP Selection Page")



        try:

            # CRITICAL: Clean up TGC cookies at the start of PSP phase to prevent conflicts

            logger.info("[PSP-START] Performing aggressive TGC cookie cleanup")

            self._cleanup_tgc_cookies()  # Initial cleanup

            self._verify_tgc_state("PSP-START")

            # Use the response from voucher page continue

            if not hasattr(self, 'voucher_continue_response') or not self.voucher_continue_response:

                logger.error("[ERROR] No voucher continue response available")

                return False



            response = self.voucher_continue_response

            current_url = str(response.url)



            # Check if we're on the PSP selection page

            if 'psp-selection' not in current_url.lower():

                logger.warning(f"[WARNING] Expected PSP selection page, got: {current_url}")

                # Derive PSP URL from current (voucher ?7 -> psp-selection ?8)

                import re

                match = re.search(r"\?(\d+)", current_url)

                if match:

                    page_num = int(match.group(1)) + 1  # ?7 -> ?8

                else:

                    page_num = 8  # Fallback

                psp_url = current_url.replace('/voucher', '/psp-selection').replace(f'?{page_num-1}', f'?{page_num}')

                if '/coe/' not in psp_url:

                    psp_url = psp_url.replace('https://www.goethe.de/', 'https://www.goethe.de/coe/')

                logger.info(f"[NAVIGATE] Derived PSP URL: {psp_url}")

                # Specifically clean up TGC cookies before PSP navigation to prevent "Multiple cookies exist" error

                self._cleanup_tgc_cookies()

                self._verify_tgc_state("PRE-PSP-NAV")

                response = await self._safe_http_request('GET', psp_url, 'PSP selection page navigation')

                if not response:

                    logger.error("[ERROR] Failed to reach PSP selection page")

                    return False



            logger.info(f"[PSP] On PSP selection page: {str(response.url)}")



            # Save page for debugging

            self.debug_save_page(response.text, "psp_selection_page")



            # Look for continue button using similar logic

            soup = BeautifulSoup(response.text, 'html.parser')

            continue_link = None

            continue_button = None



            logger.info("[CONTINUE] Searching for continue button on PSP selection page...")



            # Strategy 1: Look for nextLink pattern in href

            all_links = soup.find_all('a', href=True)

            for link in all_links:

                link_href = link.get('href', '')

                if 'nextLink' in link_href:

                    continue_link = urljoin(str(response.url), link_href)

                    logger.info(f"[FOUND] Continue nextLink: {continue_link}")

                    break



            # Strategy 2: Look for buttons with continue-related text

            if not continue_link:

                all_buttons = soup.find_all('button')

                for button in all_buttons:

                    button_text = button.get_text(strip=True).upper()

                    if any(word in button_text for word in ['CONTINUE', 'NEXT', 'PROCEED', 'WEITER']):

                        continue_button = button

                        logger.info(f"[FOUND] Continue button: {button.get('id', '')} - '{button_text}'")

                        break



            # Execute continue action using direct AJAX call
            logger.info("[CONTINUE] Extracting navSection-nextLink from PSP selection page...")

            # Use the new AJAX extraction method
            ajax_response = await self.extract_and_call_ajax_continue(response, str(response.url), "psp-selection")

            if ajax_response:
                response = ajax_response
                logger.info(f"[SUCCESS] Navigated from PSP selection to: {str(response.url)}")
            else:
                logger.error("[ERROR] Failed to navigate from PSP selection page")
                return False



            # Store response for next phase

            self.psp_continue_response = response

            logger.info(f"[SUCCESS] Continued from PSP selection page to: {str(response.url)}")

            return True



        except Exception as e:

            logger.error(f"[ERROR] Phase 4 failed: {e}")

            return False



    async def phase_5_summary_and_order(self) -> bool:
        
        import re

        """Phase 5: Handle summary page and 'Order Subject to Charge' button"""

        logger.info(">>> Phase 5: Handle Summary Page and Order")

        # Clean TGC cookies at phase start
        self._cleanup_tgc_cookies()

        try:

            # Use the response from PSP selection page continue

            if not hasattr(self, 'psp_continue_response') or not self.psp_continue_response:

                logger.error("[ERROR] No PSP continue response available")

                return False



            response = self.psp_continue_response

            current_url = str(response.url)



            # Check if we're on the summary page

            if 'summary' not in current_url.lower():

                logger.warning(f"[WARNING] Expected summary page, got: {current_url}")

                # Try to navigate to summary page

                summary_url = current_url.replace('/psp-selection', '/summary')

                if '?' in current_url:

                    summary_url = re.sub(r'\?\d+', '?9', summary_url)

                else:

                    summary_url += '?9'

                logger.info(f"[NAVIGATE] Attempting to reach summary page: {summary_url}")

                response = await self._safe_http_request('GET', summary_url, 'Summary page navigation')

                if not response:

                    logger.error("[ERROR] Failed to reach summary page")

                    return False



            logger.info(f"[SUMMARY] On summary page: {str(response.url)}")



            # Save page for debugging

            self.debug_save_page(response.text, "summary_page")



            # Look for 'Order Subject to Charge' button

            soup = BeautifulSoup(response.text, 'html.parser')

            order_button = None

            order_onclick = None



            logger.info("[ORDER] Searching for 'Order Subject to Charge' button...")



            # Strategy 1: Find button by text content

            for element in soup.find_all(['button', 'a', 'input']):

                element_text = element.get_text(strip=True).upper()

                if ('ORDER' in element_text and

                    ('SUBJECT' in element_text and 'CHARGE' in element_text) or

                    'KOSTENPFLICHTIG' in element_text or

                    'BESTELLEN' in element_text):

                    order_button = element

                    logger.info(f"[FOUND] Order button: {element.name}, id='{element.get('id', '')}', text='{element_text}'")



                    # Check for onclick handler

                    onclick = element.get('onclick', '')

                    if onclick:

                        order_onclick = onclick

                        logger.info(f"[ONCLICK] Found onclick handler: {onclick[:100]}...")

                    break



            if not order_button:

                logger.error("[ERROR] Could not find 'Order Subject to Charge' button")

                return False



            # Solve reCAPTCHA if present (v2 or v3) using the central handler
            captcha_token = await self._check_and_solve_captcha_if_present(response)



            # For the order button, we still need to extract its specific AJAX URL from page scripts
            logger.info("[ORDER] Extracting order button AJAX URL from page scripts...")

            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script', type='text/javascript')
            order_ajax_url = None

            for script in scripts:
                script_text = script.get_text() if script else ""
                
                if 'Wicket.Ajax.ajax' in script_text:
                    # Look for the nextLink URL (order button uses the same pattern)
                    import re
                    pattern = r'Wicket\.Ajax\.ajax\(\{"u":"([^"]*navSection-nextLink[^"]*)"'
                    matches = re.findall(pattern, script_text)
                    
                    if matches:
                        for match in matches:
                            relative_url = match
                            if relative_url.startswith('./'):
                                relative_url = relative_url[2:]
                            order_ajax_url = urljoin(str(response.url), relative_url)
                            logger.info(f"[ORDER] Found order AJAX URL: {order_ajax_url}")
                            break
                
                if order_ajax_url:
                    break
            
            if order_ajax_url:
                # Add timestamp
                import time
                timestamp = int(time.time() * 1000)
                order_ajax_url += f"&_={timestamp}" if '?' in order_ajax_url else f"?_={timestamp}"
                
                # Add URL validation
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(order_ajax_url)
                    if not parsed.scheme or not parsed.netloc:
                        logger.error(f"[URL-ERROR] Constructed invalid URL: {order_ajax_url}")
                        return None
                except Exception as e:
                    logger.error(f"[URL-ERROR] URL validation failed: {e}")
                    return None
                
                logger.info(f"[ORDER] Sending order request to: {order_ajax_url}")
                
                # Send the order request
                order_response = await self.session.get(
                    order_ajax_url,
                    headers={
                        'Accept': 'text/html, */*; q=0.01',
                        'X-Requested-With': 'XMLHttpRequest',
                        'Referer': str(response.url)
                    }
                )
                
                # Handle ajax-location response
                if 'ajax-location' in order_response.headers:
                    payment_url = order_response.headers['ajax-location']
                    if payment_url.startswith('../'):
                        base_url = str(response.url).rsplit('/', 1)[0]
                        payment_url = urljoin(base_url + '/', payment_url)
                    elif payment_url.startswith('./'):
                        payment_url = urljoin(str(response.url), payment_url[2:])
                    else:
                        payment_url = urljoin(str(response.url), payment_url)
                    
                    logger.info(f"[ORDER-REDIRECT] Following to payment page: {payment_url}")
                    order_response = await self.session.get(payment_url)
                
                if not order_response:
                    logger.error("[ERROR] Failed to click order button")
                    return False
            else:
                logger.error("[ERROR] Could not find order button AJAX URL")
                return False






            logger.info(f"[ORDER] Order button clicked successfully: {str(order_response.url)}")



            # Store final response

            self.final_order_response = order_response

            final_url = str(order_response.url)



            logger.info(f"[SUCCESS] Order submitted successfully!")

            logger.info(f"[PAYMENT] Final URL: {final_url}")



            # Save final page for debugging

            self.debug_save_page(order_response.text, "final_payment_page")



            return True



        except Exception as e:

            logger.error(f"[ERROR] Phase 5 failed: {e}")

            return False



    async def phase_6_open_payment_browser(self, final_modules_list: List[str] = None) -> bool:

        """Phase 6: Open payment page in browser, using the provided final module list for the banner."""

        self._log(logging.INFO, ">>> Phase 6: Open Payment Page in Browser with Session Transfer")



        try:

            if not hasattr(self, 'final_order_response') or not self.final_order_response:

                logger.error("[ERROR] No final order response available")

                return False

            final_url = str(self.final_order_response.url)



            logger.info(f"[BROWSER] Final URL: {final_url}")



            # Verify we have a reasonable URL to open

            if not final_url or final_url == 'None':

                logger.error("[ERROR] No valid URL to open in browser")

                return False



            # Check if Playwright is available

            if not PLAYWRIGHT_AVAILABLE:

                logger.warning("[FALLBACK] Playwright not available, using simple browser opening")

                import webbrowser

                webbrowser.open(final_url)

                logger.info("[MANUAL] Please complete the payment manually in the browser.")

                return True



            # Extract session cookies for transfer to browser

            session_cookies = self._extract_session_cookies()



            logger.info(f"[BROWSER] Launching browser with {len(session_cookies)} session cookies...")

            # --- THIS IS THE FIX ---
            # Parse the bot's proxy string into the format Playwright needs
            playwright_proxy = self._parse_proxy()
            
            # Launch Playwright browser with session cookies AND PROXY
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=False,  # Show browser for manual payment
                    proxy=playwright_proxy,  # Apply the parsed proxy settings here
                    args=[

                        '--disable-blink-features=AutomationControlled',

                        '--disable-web-security',

                        '--disable-features=VizDisplayCompositor',

                        '--disable-infobars',

                        '--disable-extensions',

                        '--no-first-run',

                        '--disable-default-apps'

                    ]

                )



                # Create new context with session cookies

                context = await browser.new_context(

                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

                )



                # Add cookies to context

                if session_cookies:

                    try:

                        await context.add_cookies(session_cookies)

                        self._log(logging.INFO, f"[BROWSER] ✅ Added {len(session_cookies)} cookies to browser context")

                    except Exception as cookie_error:

                        self._log(logging.WARNING, f"[BROWSER] ⚠️ Failed to add some cookies: {cookie_error}")



                # Navigate to payment page

                page = await context.new_page()



                self._log(logging.INFO, f"[BROWSER] 🌐 Navigating to payment page: {final_url}")



                try:

                    await page.goto(final_url, wait_until='networkidle', timeout=30000)

                    self._log(logging.INFO, "[BROWSER] ✅ Payment page loaded successfully")

                    # Inject the confirmation banner
                    try:
                        # --- THIS IS THE FIX ---
                        # Use the ACCURATE list passed to this function
                        self._log(logging.INFO, f"[BANNER-DEBUG] final_modules_list={final_modules_list}, final_booked_modules={getattr(self, 'final_booked_modules', None)}, selected_modules={self.selected_modules}")
                        modules_to_display = final_modules_list if final_modules_list else (self.final_booked_modules if self.final_booked_modules else self.selected_modules)

                        if modules_to_display:
                            self._log(logging.INFO, f"[BANNER] Injecting banner for ACTUAL booked modules: {modules_to_display}")
                            
                            js_code = """
                            (modules) => {
                                // Remove any existing banner to prevent duplicates on page reloads
                                const existingBanner = document.getElementById('module-confirmation-banner');
                                if (existingBanner) {
                                    existingBanner.remove();
                                }

                                const banner = document.createElement('div');
                                banner.id = 'module-confirmation-banner';
                                
                                // Banner Styling
                                banner.style.position = 'fixed';
                                banner.style.top = '0';
                                banner.style.left = '0';
                                banner.style.width = '100%';
                                banner.style.padding = '12px';
                                banner.style.backgroundColor = '#1E88E5'; // A nice, clear blue
                                banner.style.color = 'white';
                                banner.style.textAlign = 'center';
                                banner.style.fontSize = '16px';
                                banner.style.fontWeight = 'bold';
                                banner.style.zIndex = '999999';
                                banner.style.fontFamily = 'Arial, sans-serif';
                                banner.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
                                
                                // Banner Content
                                banner.innerHTML = `✅ **Modules Booked:** ${modules.join(' + ')}`;
                                
                                // Add banner to the page
                                document.body.prepend(banner);
                            }
                            """
                            await page.evaluate(js_code, modules_to_display)
                            self._log(logging.INFO, "[BANNER] ✅ Confirmation banner successfully injected.")
                        else:
                            self._log(logging.WARNING, "[BANNER] Could not determine modules to display in banner.")

                    except Exception as banner_error:
                        self._log(logging.ERROR, f"[BANNER] ❌ Failed to inject confirmation banner: {banner_error}")

                except Exception as nav_error:

                    self._log(logging.WARNING, f"[BROWSER] ⚠️ Navigation issue: {nav_error}")

                    self._log(logging.INFO, "[BROWSER] Attempting to continue anyway...")



                # Check if we're on the correct page

                current_page_url = page.url

                self._log(logging.INFO, f"[BROWSER] Current page: {current_page_url}")



                # Look for payment-related elements to confirm we're on the right page

                try:

                    # Wait a bit for page to fully load

                    # await asyncio.sleep(2)  # Commented out for maximum speed



                    # Check for common payment page indicators

                    payment_indicators = [

                        'piq-cashier', 'payment', 'pay', 'checkout', 'credit',

                        'visa', 'mastercard', 'paypal'

                    ]



                    page_content = await page.content()

                    is_payment_page = any(indicator.lower() in page_content.lower()

                                        for indicator in payment_indicators)



                    if is_payment_page:

                        logger.info("[BROWSER] ✅ Detected payment page elements - ready for manual payment")

                    else:

                        logger.info("[BROWSER] ℹ️ May need to navigate to payment section manually")



                except Exception as check_error:

                    logger.warning(f"[BROWSER] ⚠️ Could not verify payment page: {check_error}")



                # Provide user instructions

                logger.info("=" * 50)

                logger.info("[MANUAL] 🎉 BOOKING SUCCESSFUL! Payment page is now open.")

                logger.info("[MANUAL] 💳 Please complete the payment process in the browser window.")

                logger.info("[MANUAL] 📋 Steps to complete:")

                logger.info("[MANUAL]   1. Fill in your payment details")

                logger.info("[MANUAL]   2. Complete the payment process")

                logger.info("[MANUAL]   3. Wait for payment confirmation")

                logger.info("[MANUAL]   4. Close the browser when finished")

                logger.info("[MANUAL] 🔒 Your session has been transferred to the browser automatically.")

                logger.info("[MANUAL] Browser will remain open for manual payment completion.")

                logger.info("[MANUAL] Auto-refresh has been disabled to prevent interruption.")

                logger.info("=" * 50)



                # Keep the browser open by waiting for user to close it

                try:

                    logger.info("[WAITING] Waiting for user to complete payment and close browser...")

                    # Check every 5 seconds instead of every second to reduce CPU usage

                    while not page.is_closed():

                        await asyncio.sleep(5)

                    logger.info("[BROWSER] User closed the browser page")

                except KeyboardInterrupt:

                    logger.info("[BROWSER] Process interrupted by user")

                except Exception as wait_error:

                    logger.warning(f"[BROWSER] Wait error: {wait_error}")



                # Clean up

                try:

                    await context.close()

                    await browser.close()

                except:

                    pass



                logger.info("[BROWSER] ✅ Browser session completed")

                return True



        except Exception as e:

            logger.error(f"[ERROR] Phase 6 failed: {e}")

            import traceback

            logger.debug(f"[ERROR] Traceback: {traceback.format_exc()}")

            return False



    async def book_slot(self, exam_url: str, email: str, password: str,
                    modules: List[str] = None, monitor_interval: float = 0.1,
                    anti_bot_level: str = "moderate", is_flexible: bool = False,
                    skip_monitoring: bool = False) -> str:
        """Complete booking workflow. Opens browser on success. Returns status string."""
        if modules is None:
            modules = ['READING', 'LISTENING']
        self.selected_modules = modules
        self.adjust_anti_bot_settings(anti_bot_level)
        self._log(logging.INFO, f"[BOOKING] Starting booking process with {anti_bot_level} anti-bot protection")

        try:
            # Phase 1 & 2 Entry Point Logic
            if skip_monitoring:
                self._log(logging.INFO, ">>> Phase 1: Skipped (direct entry to booking funnel)")
                # When skipping, exam_url is the direct module page link
                response = await self.phase_2_breakthrough_module_page(exam_url)
                if not response:
                    self._log(logging.ERROR, "Failed to break through to module page.")
                    return 'FAILED'
                # If we are here after skipping, the 'response' from breakthrough is now the current page
                if not await self.phase_2_module_selection_and_booking(modules, is_flexible, initial_response=response):
                    return 'FAILED'
            else:
                # Normal start: Monitor the main exam page first
                monitor_response = await self.phase_1_monitor_exam_url(exam_url, monitor_interval)
                if not monitor_response:
                    return 'FAILED'

                # --- UPDATED NAVIGATION LOGIC ---
                self._log(logging.INFO, "[NAVIGATE] Slot found. Now navigating to the module selection page...")
                
                # First check for the exam button link
                exam_button_link_match = re.search(r"window\['examButtonLink'\]\s*=\s*['\"]([^'\"]+)['\"]\s*;", 
                                                  monitor_response.text)
                
                if exam_button_link_match and exam_button_link_match.group(1).strip():
                    # Use the extracted booking URL
                    booking_url = exam_button_link_match.group(1).strip()
                    self._log(logging.INFO, f"[URL-FOUND] Using exam button link: {booking_url}")
                    modules_page_url = booking_url
                else:
                    # Fallback to the original SELECT MODULES link search
                    soup = BeautifulSoup(monitor_response.text, 'html.parser')
                    select_modules_link = None
                    for link in soup.find_all('a', href=True):
                        if 'SELECT MODULES' in link.get_text(strip=True).upper():
                            select_modules_link = link.get('href')
                            break
                    
                    if not select_modules_link:
                        self._log(logging.ERROR, "[FATAL] Could not find the 'SELECT MODULES' link after re-monitoring.")
                        return 'FAILED'

                    modules_page_url = urljoin(exam_url, select_modules_link)
                
                self._log(logging.INFO, f"[NAVIGATE] Following link to: {modules_page_url}")

                # Navigate to the actual module page to get the correct content
                module_page_response = await self._safe_http_request(
                    'GET', modules_page_url, 'Navigate to module page'
                )

                if not module_page_response:
                    self._log(logging.ERROR, "[FATAL] Failed to load the module selection page.")
                    return 'FAILED'

                # Pass the CORRECT page response to the next phase
                self.current_page_response = module_page_response
                if not await self.phase_2_module_selection_and_booking(modules, is_flexible):
                    return 'FAILED'
                # --- END OF NEW FIX ---

            # The rest of the phases continue sequentially
            if not await self.phase_3_login_when_required(email, password):
                return 'FAILED'
            if not await self.phase_3_4_oska_acc_page():
                return 'FAILED'
            if not await self.phase_3_5_voucher_payment_page():
                return 'FAILED'
            if not await self.phase_4_psp_selection_page():
                return 'FAILED'
            if not await self.phase_5_summary_and_order():
                return 'FAILED'
            if not await self.phase_6_open_payment_browser(self.final_booked_modules):
                return 'FAILED'

            self._log(logging.INFO, "🎉 [SUCCESS] Booking process and browser launch completed successfully!")
            if self.stop_signal:
                self.stop_signal.set()
            return 'SUCCESS'

        except RateLimitException:
            self._log(logging.ERROR, "❌ [CRITICAL] Booking process failed due to rate-limiting.")
            return 'RATE_LIMITED'
        except Exception as e:
            import traceback
            self._log(logging.ERROR, f"❌ [CRITICAL] Booking process failed with unhandled exception: {e}\n{traceback.format_exc()}")
            return 'FAILED'
        finally:
            # Ensure cleanup happens
            try:
                if hasattr(self, 'session'):
                    await self.session.aclose()
            except:
                pass

class GoetheBookingManager:

    """Manager for multiple booking attempts"""



    def __init__(self, captcha_api_key: str, captcha_service: str = "anticaptcha", proxy: Optional[str] = None):

        self.captcha_api_key = captcha_api_key

        self.captcha_service = captcha_service

        self.proxy = proxy






