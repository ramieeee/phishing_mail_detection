from bs4 import BeautifulSoup
import requests
import urllib
import whois
import ssl, socket
from dateutil.parser import parse
from tld import get_tld

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.feature_list = []
        self.header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36'}
    
    # phishing = -1, suspicious = 0, normal = 1

    def get_domain_url(self, url):
        domain = ''
        cnt = 0
        for i in url:
            if i == '/':
                cnt += 1
            if cnt == 3:
                break
            if cnt == 2:
                domain += i
        domain = domain[1:]
        return domain
    
    #01. 문자열 길이
    def count_characters(self):
        if len(self.url) > 75: # when phishing
            self.feature_list.append(-1)
        elif len(self.url) >= 54 and len(self.url) < 75:  # when suspicious
            self.feature_list.append(0)
        else: # when not fishing
            self.feature_list.append(1)
    
    #02. URL에 '@'문자 포함 여부
    def contain_at(self):
        if '@' in self.url:
            self.feature_list.append(-1)
        else :
            self.feature_list.append(1)
    
    #03. URL에 '-' 문자 포함 여부
    def contain_dash(self):
        if '-' in self.url:
            self.feature_list.append(-1)
        else :
            self.feature_list.append(1)

    #04. HTTPS 위장 사용 여부
    def contain_HTTPS_dot(self):
        temp = self.url.lower()
        if 'https.' in temp:
            self.feature_list.append(-1)
        else:
            self.feature_list.append(1)

    #05. 외부 요청 URL 비율
    def find_link_href(self):
        try:
            html = requests.get(url, headers=self.header, timeout=4.0).text
            soup = BeautifulSoup(html, "html.parser")
            find_link = soup.find_all('link')
            find_href = soup.find_all('href')
            link_cnt = 0
            href_cnt = 0

            for i in range(len(find_link)):
                if self.get_domain_url(self.url) not in str(find_link[i]):
                    link_cnt += 1

            for i in range(len(find_href)):
                if self.get_domain_url(self.url) not in str(find_href[i]):
                    href_cnt += 1

            if self.link_in_href_rate(link_cnt, href_cnt) == 0:
                feature5 = 1
            elif self.link_in_href_rate(link_cnt, href_cnt) >= 61:
                feature5 = -1
            elif self.link_in_href_rate(link_cnt, href_cnt) >= 22 and self.link_in_href_rate(link_cnt, href_cnt) < 61:
                feature5 = 0
            else:
                self.feature_list.append(1)
        except requests.exceptions.Timeout:
            feature5 = 0
        except requests.exceptions.TooManyRedirects:
            feature5 = -1
        except requests.exceptions.RequestException:
            feature5 = -1
        except:
            feature5 = -1
        self.feature_list.append(feature5)


    def link_in_href_rate(self, link_cnt,href_cnt):
        if link_cnt ==0 and href_cnt ==0:
            return 0
        elif href_cnt >= 1 and link_cnt ==0:
            return 70
        else:
            link_in_href_rate_result = (href_cnt/link_cnt)*100
        return link_in_href_rate_result
    
    #06. HTML 소스코드의 길이
    def domain_in_length(self):
        try:
            html = requests.get(self.url, headers=self.header, timeout=5).text
            if len(html) < 5000:
                feature6 = -1
            elif len(html) < 50000:
                feature6 = 0
            else:
                feature6 = 1
        except:
            feature6 = -1
        self.feature_list.append(feature6)

    #07. SSL 인증서 검증
    def SSLfinal_State(self):
        try:
            domain = self.get_domain(self.url)
            s = self.https_connect(domain)
            if s == 0:
                feature7 = -1
            else :
                cert = s.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                issued_by = issuer['organizationName']
    
                trusted_issuer_list = self.get_trusted_issuer()
                for trusted_issuer in trusted_issuer_list:
                    if trusted_issuer == issued_by:
                        break
                    else:
                        feature7 = 1
    
                notAfter = cert['notAfter']
                notBefore = cert['notBefore']
                init_date = parse(notBefore)
                expiration_date = parse(notAfter)
                total_days = (expiration_date.date() - init_date.date()).days
                if total_days >= 365:
                    feature7 = -1
                else:
                    feature7 = 1
        except:
            feature7 = -1
        self.feature_list.append(feature7)
    
    def https_connect(self):
        try:
            TIMEOUT = 4.0
            socket.setdefaulttimeout(TIMEOUT)
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(socket.socket(), server_hostname=self.url)
            s.connect((self.url, 443))
            return s
        except:
            s = 0
            return s
    
    def get_trusted_issuer(self):
        f = open("CA_list.txt", "r")
    
        trusted_issuer = []
        for line in f:
            issuers = line.strip('\n')
            trusted_issuer.append(issuers)
        return trusted_issuer
    
    #08. 도메인 생성기간으로 탐지
    def domain_registration_period(self):
        try:
            total_date = self.get_total_date(self.url)
            if total_date <= 365:
                feature8 = -1
            else:
                feature8 = 1
        except:
            feature8 = -1
        self.feature_list.append(feature8)

    def get_total_date(self):
        try:
            TIMEOUT=3.0
            socket.setdefaulttimeout(TIMEOUT)
            domain = whois.whois(self.url)
        except:
            return 0
        if domain.expiration_date is None:
            return 0
        if domain.updated_date is None:
            return 0 
        if type(domain.expiration_date) is list:
            expiration_date = domain.expiration_date[0]
        else:
            expiration_date = domain.expiration_date
        
        if type(domain.updated_date) is list:
            updated_date = domain.updated_date[0]
        else:
            updated_date = domain.updated_date
        
        total_date = (expiration_date - updated_date).days
        return total_date
    
    #09. Alexa 랭킹 기준으로 탐지
    def check_alexa_rank(self):
        try:
            domain = self.get_domain(self.url)
            rank_str = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url="+ domain).read(), 'xml').find("REACH")['RANK']
            rank_str1 = int(rank_str)
            if rank_str1 < 100000:
                feature9 = 1
            else:
                feature9 = -1
        except:
            feature9 = -1
        self.feature_list.append(feature9)
    
    #10 사이트 포트열림 확인
    def port_open_check(self):
        feature10 = 1
        try:
            ip = self.get_domain(self.url)
        except:
            feature10 = -1
    
        ports = [80, 21, 22, 23, 443, 445, 1433, 1521, 3306, 3389]
        for port in ports :
            socket.setdefaulttimeout(1.5)
            s = socket.socket()
            if port == 80 and 443 :
                try:
                    s.connect((ip, port))
                    s.close()
                    feature10 = 1
                except:
                    feature10 = -1
            else:
                try :
                    s.connect((ip, port))
                    s.close()
                    feature10 = -1
                except :
                    feature10 = 1
                    pass
        self.feature_list.append(feature10)

    #11. 서브 도메인 개수 
    def having_sub_domain(self):
        try:
            url = self.remove_www(self.url)
            domain = get_tld(url, as_object=True)
            dot = domain.subdomain.count('.')
            if domain.subdomain == "":
                feature11 = 1
            elif dot == 0:
                feature11 = 0
            else:
                feature11 = -1
        except: 
            feature11 = -1
        self.feature_list.append(feature11)

    def remove_www(self):
        if "www." in self.url[:12] :
            url = self.url.replace("www.", "")
        return url

    #12. '//' 를 사용하는 리다이렉션 체크
    def double_slash_redirecting(self):
        parse = urllib.parse.urlparse(self.url)
        path = parse.path
        if '//' in path:
            feature12 = -1
        else:
            feature12 = 1
        self.feature_list.append(feature12)

    #13.  URL 단축 서비스 
    def shortening_service(self):
        try:
            response = requests.get(self.url,headers=self.header,timeout = 3)
            if response.status_code== 301 or response.status_code == 302  :
                feature13 = -1
            else:
                feature13 = 1
        except:
            feature13 = -1
        self.feature_list.append(feature13)


    # 실행 함수
    def run_process(self):
        self.count_characters() # 1
        self.contain_at() # 2
        self.contain_dash() # 3
        self.contain_HTTPS_dot() # 4
        self.find_link_href() # 5
        self.domain_in_length() # 6
        self.SSLfinal_State() # 7
        self.domain_registration_period() # 8
        self.check_alexa_rank() # 9
        self.port_open_check() # 10
        self.having_sub_domain() # 11
        self.double_slash_redirecting() # 12
        self.shortening_service() # 13
        return self.feature_list