

import requests
from bs4 import BeautifulSoup

url=input("Enter url: ")
res=requests.get(url)
type(res)

soup = BeautifulSoup(res.content, 'html.parser')

for links in soup.find_all('a'):
    print(links.get('href'))
























