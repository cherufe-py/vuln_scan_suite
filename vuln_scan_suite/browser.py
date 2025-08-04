from time import sleep

from selenium import webdriver
from selenium.common import NoAlertPresentException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.support.wait import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager


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
        self.default_wait_time = 10
        self.driver.implicitly_wait(self.default_wait_time)
        self.wait = WebDriverWait(self.driver, 10)

    def quit(self):
        self.driver.quit()

    def extract_alert_content(self, wait_time=3, attempts=2) -> str:
        while attempts:
            try:
                sleep(wait_time)
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                return alert_text
            except NoAlertPresentException:
                attempts -= 1
        return ""

    def is_element_available(self, by, criteria, wait_time=5):
        try:
            self.driver.implicitly_wait(wait_time)
            self.driver.find_element(by, criteria)
            self.driver.implicitly_wait(self.default_wait_time)
            return True
        except:
            self.driver.implicitly_wait(self.default_wait_time)
            return False
