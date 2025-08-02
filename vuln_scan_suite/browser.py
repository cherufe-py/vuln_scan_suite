from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import time


class Browser:
    def __init__(self, headless: bool = True, wait_time: int = 2):
        self.wait_time = wait_time
        chrome_options = Options()
        if headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        self.driver = webdriver.Chrome(
            service=ChromeService(ChromeDriverManager().install()),
            options=chrome_options
        )

    def get_page_source(self, url: str) -> str:
        self.driver.get(url)
        time.sleep(self.wait_time)  # Wait for JavaScript to execute
        return self.driver.page_source

    def contains(self, url: str, payload: str) -> bool:
        html = self.get_page_source(url)
        return payload in html

    def quit(self):
        self.driver.quit()
