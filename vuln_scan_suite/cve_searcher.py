import urllib.request

from bs4 import BeautifulSoup


class CveSearcher(object):
    cve_searcher_url = "https://cve.mitre.org/cgi-bin/cvekey.cgi"
    url_search_suffix = "?keyword="

    def search_by_keywords(self, *args):
        url_to_search = self.get_url_to_search(args)

        soup = self.perform_search_and_get_soup(url_to_search)

        table_containter = soup.find('div', attrs={"id": "TableWithRules"})
        print(table_containter)

        for row in table_containter.find_all('tr')[1:] if table_containter else []:
            cols = row.find_all('td')
            if len(cols) == 2:
                link_tag = cols[0].find('a')
                link = link_tag['href'] if link_tag else ''
                description = cols[1].text.strip()
                print(f"{link} -> {description}")

    def perform_search_and_get_soup(self, url_to_search):
        with urllib.request.urlopen(url_to_search) as response:
            html = response.read()
        soup = BeautifulSoup(html, 'html.parser')
        return soup

    def get_url_to_search(self, args):
        url_to_use = f"{self.cve_searcher_url}{self.url_search_suffix}{'+'.join(args)}"
        return url_to_use
