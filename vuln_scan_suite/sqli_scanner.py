from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from tqdm import tqdm

from vuln_scan_suite.browser import Browser
from vuln_scan_suite.constants import SQLI_PAYLOADS


def scan_sqli(login_webpage_url: str, username_form_field: str, password_form_field: str) -> str | None:
    browser = Browser(headless=True)
    progress_bar = tqdm(SQLI_PAYLOADS, desc="Scanning forms...")
    for payload in progress_bar:
        try:
            browser.driver.get(login_webpage_url)

            form = browser.wait.until(
                EC.presence_of_element_located((By.XPATH, f"//form[//input[@name='{username_form_field}']]")))
            form.find_element(By.NAME, username_form_field).send_keys(payload)
            form.find_element(By.NAME, password_form_field).send_keys('lol')
            form.find_element(By.XPATH, ".//*[@type='submit']").click()
            if not browser.is_element_available(By.NAME, username_form_field):
                print("SQLi Found: ", payload)
                browser.quit()
                progress_bar.close()
                return payload
        except:
            pass
    browser.quit()
    return None


if __name__ == "__main__":
    target = input("Enter target URL (e.g. http://localhost/login.php): ")
    username = input("Provide username field name: ")
    password = input("Provide password field name: ")
    scan_sqli(target, username, password)
