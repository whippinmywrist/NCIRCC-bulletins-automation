import requests
from bs4 import BeautifulSoup
from jinja2 import Template
import smtplib
from email.message import EmailMessage
import pickle

template = """
        <dl class="inline">
            <dt>Summary</dt><dd>{{ a.title }}</dd>
            <dt>Дата публикации</dt><dd>{{ a.publication_date }}</dd>
            <dt>Дата выявления</dt><dd>{{ a.detection_date }}</dd>
            <dt>Производитель ПО</dt><dd>{{ a.vendor }}</dd>
            <dt>Наименование ПО</dt><dd>{{ a.products|join(', ') }}</dd>
            <dt>Уровень опасности</dt><dd>{{ a.severity }}</dd>
            <dt>CVSSv3 Score</dt><dd>{{ a.cvss_v3_score }} - {{ a.severity }}</dd>
            <dt>Links</dt><dd>{{ a.bulletin_pdf_url }}</dd>
        </dl>"""


def get_bulletins(page=1):
    r = requests.get("https://safe-surf.ru/specialists/bulletins-nkcki/?PAGEN_1={}".format(page))
    soup = BeautifulSoup(r.text, "html.parser")
    result = {}
    for vuln in soup.find_all("div", "blockBase blockBulletine"):
        title = vuln.find('h4').text.strip()
        bulletin_pdf_url = "https://safe-surf.ru{}".format(vuln.find('h4').find('a')['href'])
        result.update(
            {
                title: {
                    'title': title,
                    'bulletin_pdf_url': bulletin_pdf_url
                }
            })
        for line in vuln.find_all('div', 'stringBase clearfix'):
            # print(line.text)
            if 'Дата:' in line.text:
                publication_date = " ".join(line.text.replace('Дата:', '').split())
                result[title]['publication_date'] = publication_date
            if 'Дата выявления:' in line.text:
                detection_date = " ".join(line.text.replace('Дата выявления:', '').split())
                result[title]['detection_date'] = detection_date
            if 'Производитель ПО:' in line.text:
                vendor = " ".join(line.text.replace('Производитель ПО:', '').split())
                result[title]['vendor'] = vendor
            if 'Наименование ПО:' in line.text:
                products = []
                for product in line.text.replace('Наименование ПО:', '').split('\n\n\n\n'):
                    p = " ".join(product.split())
                    if p != '':
                        products.append(p)
                result[title]['products'] = products
            if 'Уровень опасности:' in line.text:
                a = " ".join(line.text.replace('Уровень опасности:', '').split())
                severity = a.split(' ')[0]
                cvss_v3_score = a.split(' ')[1][1:-1]
                result[title]['severity'] = severity
                result[title]['cvss_v3_score'] = cvss_v3_score
    return result


if __name__ == '__main__':
    a = get_bulletins()
    b = get_bulletins(page=2)
    c = get_bulletins(page=3)
    d = {**a, **b, **c}
    jinja_template = Template(template)
    EMAIL_HOST = ''
    EMAIL_PORT = 465
    EMAIL_HOST_PASSWORD = ''
    EMAIL_HOST_USER = ''
    with open('bulletins.pickle', 'rb+') as f:
        old_data = pickle.load(f)
    for title in d.keys():
        if title not in old_data:
            msg = EmailMessage()
            body = jinja_template.render(title=title, a=a[title])
            msg['Subject'] = '[НКЦКИ] Уязвимости в ' + ", ".join(a[title]['products']) + ' / '
            msg['From'] = EMAIL_HOST_USER
            msg['To'] = ''
            msg.set_content(body)
            smtp_server = smtplib.SMTP_SSL(host=EMAIL_HOST, port=EMAIL_PORT)
            try:
                smtp_server.login(user=EMAIL_HOST_USER, password=EMAIL_HOST_PASSWORD)
                smtp_server.send_message(msg)
                print('Email sended {}'.format(msg['Subject']))
            except Exception as e:
                print('Error sending email. Details: {} - {}'.format(e.__class__, e))
                d.pop(title)
    with open('bulletins.pickle', 'wb') as f:
        pickle.dump({**d, **old_data}, f)
