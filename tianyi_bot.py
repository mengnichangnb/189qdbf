import time
import re
import json
import base64
import hashlib
import rsa
import requests
import os
import sys
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

class Config:
    """
    配置类，管理所有常量和URL。
    """
    # 加密常量
    BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
    B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    # API端点
    LOGIN_TOKEN_URL = "https://m.cloud.189.cn/udb/udb_login.jsp?pageId=1&pageKey=default&clientType=wap&redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html"
    LOGIN_SUBMIT_URL = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    SIGN_URL_TEMPLATE = "https://api.cloud.189.cn/mkt/userSign.action?rand={}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K"

    # 抽奖URL
    DRAW_URLS = [
        "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN",
        "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN",
        "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN"
    ]

    # 请求头
    LOGIN_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
        'Referer': 'https://open.e.189.cn/',
    }

    SIGN_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
        "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host": "m.cloud.189.cn",
        "Accept-Encoding": "gzip, deflate",
    }


class CryptoUtils:
    """
    加密工具类。
    """
    @staticmethod
    def int2char(a: int) -> str:
        """整数转字符。"""
        return Config.BI_RM[a]

    @staticmethod
    def b64tohex(a: str) -> str:
        """Base64转十六进制。"""
        d = ""
        e = 0
        c = 0
        for i in range(len(a)):
            if list(a)[i] != "=":
                v = Config.B64MAP.index(list(a)[i])
                if 0 == e:
                    e = 1
                    d += CryptoUtils.int2char(v >> 2)
                    c = 3 & v
                elif 1 == e:
                    e = 2
                    d += CryptoUtils.int2char(c << 2 | v >> 4)
                    c = 15 & v
                elif 2 == e:
                    e = 3
                    d += CryptoUtils.int2char(c)
                    d += CryptoUtils.int2char(v >> 2)
                    c = 3 & v
                else:
                    e = 0
                    d += CryptoUtils.int2char(c << 2 | v >> 4)
                    d += CryptoUtils.int2char(15 & v)
        if e == 1:
            d += CryptoUtils.int2char(c << 2)
        return d

    @staticmethod
    def rsa_encode(j_rsakey: str, string: str) -> str:
        """RSA加密。"""
        rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
        result = CryptoUtils.b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
        return result

class TianYiCloudBot:
    """
    天翼云盘自动签到和抽奖机器人。
    """
    def __init__(self, username: str, password: str, account_id: str = ""):
        self.username = username
        self.password = password
        self.account_id = account_id or f"账户{username[:3]}***"
        self.session = requests.Session()

    def _extract_login_params(self, html: str) -> Dict[str, str]:
        """从HTML中提取登录参数。"""
        try:
            return {
                'captchaToken': re.findall(r"captchaToken' value='(.+?)'", html)[0],
                'lt': re.findall(r'lt = "(.+?)"', html)[0],
                'returnUrl': re.findall(r"returnUrl= '(.+?)'", html)[0],
                'paramId': re.findall(r'paramId = "(.+?)"', html)[0],
                'j_rsakey': re.findall(r'j_rsaKey" value="(\S+)"', html, re.M)[0]
            }
        except (IndexError, AttributeError) as e:
            raise Exception(f"提取登录参数失败: {e}")

    def login(self) -> bool:
        """登录天翼云盘。"""
        try:
            # 步骤1：获取初始登录页面以查找重定向
            resp_token = self.session.get(Config.LOGIN_TOKEN_URL)
            match_redirect = re.search(r"https?://[^\s'\"]+", resp_token.text)
            if not match_redirect:
                print("在初始响应中找不到重定向URL。")
                return False
            
            # 步骤2：跟随重定向获取真实的登录页面URL
            resp_redirect = self.session.get(match_redirect.group())
            match_href = re.search(r"<a id=\"j-tab-login-link\"[^>]*href=\"([^\"]+)\"", resp_redirect.text)
            if not match_href:
                print("找不到登录链接href。")
                return False

            # 步骤3：访问最终登录页面并提取参数
            resp_login_page = self.session.get(match_href.group(1))
            login_params = self._extract_login_params(resp_login_page.text)
            self.session.headers.update({"lt": login_params['lt']})

            # 步骤4：加密凭据
            encrypted_username = CryptoUtils.rsa_encode(login_params['j_rsakey'], self.username)
            encrypted_password = CryptoUtils.rsa_encode(login_params['j_rsakey'], self.password)

            # 步骤5：构建登录负载并提交
            login_data = {
                "appKey": "cloud", "accountType": '01',
                "userName": f"{{RSA}}{encrypted_username}", "password": f"{{RSA}}{encrypted_password}",
                "validateCode": "", "captchaToken": login_params['captchaToken'],
                "returnUrl": login_params['returnUrl'], "mailSuffix": "@189.cn",
                "paramId": login_params['paramId']
            }
            resp_submit = self.session.post(Config.LOGIN_SUBMIT_URL, data=login_data, headers=Config.LOGIN_HEADERS, timeout=10)
            
            # 步骤6：处理登录结果
            result = resp_submit.json()
            if result.get('result') == 0:
                self.session.get(result['toUrl']) # 访问'toUrl'以完成登录
                return True
            else:
                print(f"登录失败，信息：{result.get('msg')}")
                return False
        except Exception as e:
            print(f"登录过程中发生错误：{e}")
            return False

    def sign_in(self) -> Tuple[bool, str]:
        """执行每日签到。"""
        try:
            rand = str(round(time.time() * 1000))
            sign_url = Config.SIGN_URL_TEMPLATE.format(rand)
            response = self.session.get(sign_url, headers=Config.SIGN_HEADERS, timeout=10)
            result = response.json()
            
            netdisk_bonus = result.get('netdiskBonus', 0)
            if result.get('isSign'):
                return True, f"已签到，获得{netdisk_bonus}M空间"
            else:
                return True, f"签到成功，获得{netdisk_bonus}M空间"
        except Exception as e:
            error_msg = f"签到失败: {e}"
            print(error_msg)
            return False, error_msg

    def draw_prize(self, round_num: int, url: str) -> Tuple[bool, str]:
        """执行单次抽奖。"""
        try:
            response = self.session.get(url, headers=Config.SIGN_HEADERS, timeout=10)
            data = response.json()

            if "errorCode" in data:
                return False, f"抽奖失败，次数不足"
            else:
                prize_name = data.get("prizeName", "未知奖品")
                return True, f"抽奖成功，获得【{prize_name}】"
        except Exception as e:
            error_msg = f"第{round_num}次抽奖出错: {e}"
            print(error_msg)
            return False, error_msg

    def run(self) -> Dict[str, any]:
        """执行完整的签到和抽奖流程。"""
        results = {'account_id': self.account_id, 'login': '登录失败', 'sign_in': '未执行', 'draws': []}
        
        if not self.login():
            return results
        results['login'] = '登录成功'

        _, sign_msg = self.sign_in()
        results['sign_in'] = sign_msg

        # 并发执行抽奖
        draw_results = [None] * len(Config.DRAW_URLS)
        with ThreadPoolExecutor(max_workers=len(Config.DRAW_URLS)) as executor:
            future_to_url = {executor.submit(self.draw_prize, i + 1, url): i for i, url in enumerate(Config.DRAW_URLS)}
            for future in as_completed(future_to_url):
                index = future_to_url[future]
                try:
                    _, draw_msg = future.result()
                    draw_results[index] = draw_msg
                except Exception as exc:
                    draw_results[index] = f"第{index + 1}次抽奖产生异常: {exc}"
        
        results['draws'] = draw_results
        return results

def load_accounts_from_env() -> List[Tuple[str, str]]:
    """从环境变量加载账户凭据。"""
    load_dotenv()
    username_env = os.getenv("TYYP_USERNAME")
    password_env = os.getenv("TYYP_PSW")

    if not username_env or not password_env:
        print("错误：环境变量 TYYP_USERNAME 或 TYYP_PSW 未设置。")
        print("请在 .env 文件或系统环境中配置它们。")
        sys.exit(1)

    usernames = username_env.split('&')
    passwords = password_env.split('&')

    if len(usernames) != len(passwords):
        print("错误：用户名和密码的数量不匹配。")
        sys.exit(1)

    return list(zip(usernames, passwords))

def process_account(account_info: Tuple[int, Tuple[str, str]]) -> str:
    """
    处理单个账户（登录、签到、抽奖）并返回格式化的结果字符串。
    此函数设计为在单独的线程中运行。
    """
    i, (username, password) = account_info
    account_id = f"账户{i} ({username[:3]}***)"
    output = [f"## {account_id}"]

    try:
        bot = TianYiCloudBot(username, password, account_id)
        results = bot.run()

        output.append("### 执行结果")
        output.append(f"- **登录状态**: {results['login']}")
        output.append(f"- **签到结果**: {results['sign_in']}")

        if results['draws']:
            output.append("- **抽奖结果**:")
            # 抽奖结果按完成顺序列出
            for j, draw_result in enumerate(results['draws'], 1):
                clean_result = str(draw_result)
                if "成功" in clean_result or "获得" in clean_result:
                    output.append(f"  - 🎉 第{j}次: {clean_result}")
                else:
                    output.append(f"  - ❌ 第{j}次: {clean_result}")
    except Exception as e:
        output.append(f"### {account_id} 发生意外错误")
        output.append(f"- **错误信息**: {e}")
    
    return "\n".join(output)

def main():
    """主程序入口。"""
    start_time = datetime.now()
    print("# 天翼云盘自动签到抽奖程序（并发版）")
    print()

    accounts = load_accounts_from_env()
    # 从环境变量读取最大并发工作线程数，默认为4
    max_workers = int(os.getenv("MAX_WORKERS"， 20))

    print("## 执行概览")
    print(f"- **启动时间**: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"- **账户数量**: {len(accounts)} 个")
    print(f"- **并发线程**: {max_workers} 个")
    print("-" * 20)

    # 并发处理所有账户
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 为每个工作线程创建一个参数列表
        account_info_list = list(enumerate(accounts, 1))
        
        # map()按输入顺序返回结果
        results_list = executor.map(process_account, account_info_list)
        
        for result_str in results_list:
            print(result_str)
            print() # 添加换行符以便更好地分隔

    # 最终总结
    end_time = datetime.now()
    duration = end_time - start_time
    print("---")
    print("## 执行统计")
    print(f"- **结束时间**: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"- **总运行时长**: {duration.total_seconds():.2f} 秒")
    print()
    print("✅ **所有账户处理完成！**")

if __name__ == "__main__":
    main()
