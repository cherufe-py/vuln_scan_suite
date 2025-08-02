import urllib.request
from itertools import zip_longest
from typing import List

from bs4 import BeautifulSoup

from vuln_scan_suite.utilities import contains_digit, count_dots


class CveSearcher(object):
    cve_searcher_url = "https://cve.mitre.org/cgi-bin/cvekey.cgi"
    url_search_suffix = "?keyword="

    def perform_raw_search_by_keywords(self, *args) -> List[dict]:
        response = []
        if len(args) < 4:
            response += self.search_by_keywords(*args)
        else:
            for keywords in zip_longest(args[::2], args[1::2], fillvalue=""):
                response += self.search_by_keywords(*keywords)

        return response

    def perform_clean_search_by_keywords(self, keywords: list, items_to_return=10):
        response = []
        for key_element in self.get_important_item_for_search(keywords):
            for item in self.perform_raw_search_by_keywords(*keywords):
                if key_element in item.get("description"):
                    response.append(item)
                    if items_to_return == len(response):
                        return response

        # TODO what happens if there is no key elements to search.
        return response

    def get_important_item_for_search(self, keywords: list):
        only_keywords_with_number = list(filter(contains_digit, keywords))
        three_dots_keywords = list(filter(lambda x: count_dots(x) >= 3, only_keywords_with_number))
        two_dots_keywords = list(filter(lambda x: count_dots(x) == 2, only_keywords_with_number))
        one_dot_keywords = list(filter(lambda x: count_dots(x) == 1, only_keywords_with_number))
        zero_dot_keywords = list(filter(lambda x: count_dots(x) == 0, only_keywords_with_number))
        return three_dots_keywords + two_dots_keywords + one_dot_keywords + zero_dot_keywords

    def search_by_keywords(self, *args) -> List[dict]:
        url_to_search = self.get_url_to_search(args)

        soup = self.perform_search_and_get_soup(url_to_search)

        table_container = soup.find('div', attrs={"id": "TableWithRules"})

        response = []
        for row in table_container.find_all('tr')[1:] if table_container else []:
            cols = row.find_all('td')
            if len(cols) == 2:
                link_tag = cols[0].find('a')
                link = link_tag['href'] if link_tag else ''
                description = cols[1].text.strip()
                response.append(
                    {
                        "link": link,
                        "description": description
                    }
                )

        return response

    def perform_search_and_get_soup(self, url_to_search):
        with urllib.request.urlopen(url_to_search) as response:
            html = response.read()
        soup = BeautifulSoup(html, 'html.parser')
        return soup

    def get_url_to_search(self, args):
        url_to_use = f"{self.cve_searcher_url}{self.url_search_suffix}{'+'.join(args)}"
        return url_to_use
