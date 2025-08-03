from time import sleep
from typing import List
from urllib.parse import urlparse

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from tqdm import tqdm

from vuln_scan_suite.browser import Browser
from vuln_scan_suite.constants import FIRST_PAYLOAD_CONTENT, FORM_IDENTIFIERS
from vuln_scan_suite.utilities import get_xss_payloads


def scan_xss_for_dynamic_page(url, wait_time=3):
    browser = Browser(headless=True)
    forms_identifiers = get_forms_identifiers(url, browser)

    found_xss = []
    for forms_identifier in forms_identifiers,:
        for payload in tqdm(get_xss_payloads(FIRST_PAYLOAD_CONTENT), desc="Scanning forms..."):
            form = browser.driver.find_element(By.XPATH, f"//form{forms_identifier}")
            for text_input in get_input_text_webelements(form):
                text_input.send_keys(payload)
            for text_area in get_textarea_webelements(form):
                text_area.send_keys(payload)
            form.submit()
            alert_content = browser.extract_alert_content()
            if FIRST_PAYLOAD_CONTENT in alert_content:
                found_xss.append(payload)
        sleep(wait_time)
    browser.quit()
    return found_xss


def get_forms_identifiers(url, browser) -> List[str]:
    browser.driver.get(url)
    forms_identifiers = []
    for form in browser.driver.find_elements(By.TAG_NAME, 'form'):
        forms_identifiers.append(
            "".join([get_form_identifier(form, form_identifier) for form_identifier in FORM_IDENTIFIERS]))
    return forms_identifiers


def get_form_identifier(form: WebElement, attribute: str) -> str:
    form_attribute = form.get_attribute(attribute)
    if form_attribute:
        if attribute == 'action':
            parsed_url = urlparse(form_attribute)
            path = parsed_url.path.lstrip('/')
            return f"[@action='{path}']"
        else:
            return f"[@{attribute}='{form_attribute}']"
    return ""


def get_input_text_webelements(form: WebElement) -> List[WebElement]:
    return form.find_elements(By.XPATH, ".//input[@type='text']")


def get_textarea_webelements(form: WebElement) -> List[WebElement]:
    return form.find_elements(By.TAG_NAME, "textarea")


if __name__ == "__main__":
    target = input("Enter target URL (e.g. http://localhost/test): ")
    scan_xss_for_dynamic_page(target)
