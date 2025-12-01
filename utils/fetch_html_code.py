# used by pshell for requesting the HTML code of a URL and analyzing it. Based on the analysis, it suggests the next command to run.

import requests
from bs4 import BeautifulSoup

class HTMLFetcher:
    def __init__(self, url):
        self.url = url

    def fetch_html(self):
        try:
            response = requests.get(self.url)
            response.raise_for_status()  # Raise an error for bad responses
            return response.text
        except requests.RequestException as e:
            print(f"Error fetching HTML from {self.url}: {e}")
            return None

    def parse_html(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        return soup.prettify()  # Return a formatted version of the HTML

    def analyze_html(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string if soup.title else "No title found"
        links = [a['href'] for a in soup.find_all('a', href=True)]
        return {
            "title": title,
            "links": links,
            "text_content": soup.get_text()
        }
    
    def run(self):
        html = self.fetch_html()
        if html:
            parsed_html = self.parse_html(html)
            analysis = self.analyze_html(html)
            return {
                "parsed_html": parsed_html,
                "analysis": analysis
            }
        else:
            return None
        
def main():
    url = input("Enter the URL to fetch HTML from: ")
    fetcher = HTMLFetcher(url)
    result = fetcher.run()
    
    if result:
        print("Parsed HTML:")
        print(result["parsed_html"])
        print("\nAnalysis:")
        print(f"Title: {result['analysis']['title']}")
        print(f"Links: {result['analysis']['links']}")
        print(f"Text Content: {result['analysis']['text_content'][:200]}...")  # Print first 200 characters of text content
    else:
        print("Failed to fetch or analyze HTML.")

if __name__ == "__main__":

    main()