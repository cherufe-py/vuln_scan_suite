from typing import List

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from vuln_scan_suite.browser import Browser

FORM_IDENTIFIERS = [
    'action',
    'name',
    'id'
]

XSS_PAYLOADS = [
    "<script>alert(666)</script>",
    "\"'><img src=x onerror=alert(666)>",
    "<svg/onload=alert(666)>",
    "';alert(666);//",
]


def scan_xss(url, wait_time=3):
    browser = Browser()
    browser.driver.start()
    forms_identifiers = get_forms_identifiers(url, browser)

    found_xss = []
    for i, forms_identifier in enumerate(forms_identifiers, 1):
        form = browser.driver.find_element(By.XPATH, f"//form{forms_identifier}")
        for payload in XSS_PAYLOADS:
            for text_input in get_input_text_webelements(form):
                text_input.send_keys(payload)
            for text_area in get_textarea_webelements(form):
                text_area.send_keys(payload)
        form.submit()


def get_forms_identifiers(url, browser) -> List[str]:
    browser.driver.get(url)
    forms_identifiers = []
    for form in browser.driver.find_elements(By.TAG_NAME, 'forms'):
        forms_identifiers.append(
            "".join([get_form_identifier(form, form_identifier) for form_identifier in FORM_IDENTIFIERS]))
    return forms_identifiers


def get_form_identifier(form: WebElement, attribute: str) -> str:
    form_attribute = form.get_attribute(attribute)
    return f"[@action='{form_attribute}']" if form_attribute else ""


def get_input_text_webelements(form: WebElement) -> List[WebElement]:
    return form.find_elements(By.XPATH, ".//input[@type='text']")


def get_textarea_webelements(form: WebElement) -> List[WebElement]:
    return form.find_elements(By.TAG_NAME, "textarea")
