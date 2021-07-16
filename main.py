import requests
from bs4 import BeautifulSoup
from pprint import pprint
import time
import camelot

def get_bulletins(page=1):
    r = requests.get("https://safe-surf.ru/specialists/bulletins-nkcki/?PAGEN_1={}".format(page))
    soup = BeautifulSoup(r.text, "html.parser")
    result = {}
    for vuln in soup.find_all("div", "blockBase blockBulletine"):
        title = vuln.find('h4').text.strip()
        bulletin_pdf_url = "https://safe-surf.ru{}".format(vuln.find('h4').find('a')['href'])
        for line in vuln.find_all('div', 'stringBase clearfix'):
            #print(line.text)
            print('---------')
            if 'Дата:' in line.text:
                publication_date = " ".join(line.text.replace('Дата:', '').split())
            if 'Дата выявления:' in line.text:
                detection_date = " ".join(line.text.replace('Дата выявления:', '').split())
            if 'Производитель ПО:' in line.text:
                vendor = " ".join(line.text.replace('Производитель ПО:', '').split())
            if 'Наименование ПО:' in line.text:
                products = []
                for product in line.text.replace('Наименование ПО:', '').split('\n\n\n\n'):
                    p = " ".join(product.split())
                    if p != '':
                        products.append(p)
            if 'Уровень опасности:' in line.text:
                a = " ".join(line.text.replace('Уровень опасности:', '').split())
                severity = a.split(' ')[0]
                cvss_v3_score = a.split(' ')[1][1:-1]
        result.update(
            {
                title: {
                    'Заголовок': title,
                    'Ссылка на PDF': bulletin_pdf_url,
                    'Дата публикации': publication_date,
                    'Дата выявления': detection_date,
                    'Производитель ПО': vendor,
                    'Наименование ПО': products,
                    'Уровень опасности': severity,
                    'Оценка CVSS V3': cvss_v3_score
                }
            }
        )
    return result


if __name__ == '__main__':
    a = get_bulletins()
    pprint(a)
