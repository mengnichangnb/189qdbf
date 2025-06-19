import time
import re
import json
import base64
import rsa
import requests
import os
import sys
import random
from datetime import datetime
from typing import List, Dict, Tuple, Any
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed # 重新引入并发工具

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

    # 签到并发任务总数 (从环境变量或默认值获取)
    # MAX_WORKERS = os.getenv("MAX_WORKERS", 50) # 这个会被 main() 函数中的 MAX_WORKERS 覆盖
    
    # 新增：并发签到任务总数
    CONCURRENT_SIGN_IN_ATTEMPTS = 50
    # 新增：每次提交到线程池的任务之间引入的随机延迟范围（秒）
    SUBMIT_DELAY_MIN = 0.01
    SUBMIT_DELAY_MAX = 0.05


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
        encrypted_bytes = rsa.encrypt(f'{string}'.encode(), pubkey)
        encoded_string = base64.b64encode(encrypted_bytes).decode()
        result = CryptoUtils.b64tohex(encoded_string)
        return result

class TianYiCloudBot:
    """
    天翼云盘自动签到机器人。
    """
    def __init__(self, username: str, password: str, account_id: str = ""):
        self.username = username
        self.password = password
        self.account_id = account_id or f"账户{username[:3]}***"
        self.session = requests.Session()

    def _extract_login_params(self, html: str) -> Dict[str, str]:
        """从HTML中提取登录参数。"""
        try:
            j_rsakey_match = re.findall(r'j_rsaKey" value="(\S*)"', html, re.M)
            j_rsakey = j_rsakey_match[0] if j_rsakey_match else ""

            return {
                'captchaToken': re.findall(r"captchaToken' value='(.+?)'", html)[0],
                'lt': re.findall(r'lt = "(.+?)"', html)[0],
                'returnUrl': re.findall(r"returnUrl= '(.+?)'", html)[0],
                'paramId': re.findall(r'paramId = "(.+?)",', html)[0],
                'j_rsakey': j_rsakey
            }
        except (IndexError, AttributeError) as e:
            raise Exception(f"提取登录参数失败: {e}. 原始HTML片段: {html[:500]}")

    def login(self) -> bool:
        """登录天翼云盘。"""
        try:
            print(f"[{self.account_id}] 正在获取登录令牌页面...")
            resp_token = self.session.get(Config.LOGIN_TOKEN_URL, timeout=15) # 增加超时时间

            match_redirect = re.search(r"https?://[^\s'\"]+", resp_token.text)
            if not match_redirect:
                print(f"[{self.account_id}] 在初始响应中找不到重定向URL。")
                return False

            print(f"[{self.account_id}] 正在获取重定向页面...")
            resp_redirect = self.session.get(match_redirect.group(), timeout=15)

            match_href = re.search(r'href=["\']([^"\']+)["\']', resp_redirect.text)
            if not match_href:
                print(f"[{self.account_id}] 找不到登录链接href。")
                return False

            print(f"[{self.account_id}] 正在获取登录参数页面...")
            resp_login_page = self.session.get(match_href.group(1), timeout=15)
            login_params = self._extract_login_params(resp_login_page.text)
            self.session.headers.update({"lt": login_params['lt']})

            if login_params['j_rsakey']:
                encrypted_username = CryptoUtils.rsa_encode(login_params['j_rsakey'], self.username)
                encrypted_password = CryptoUtils.rsa_encode(login_params['j_rsakey'], self.password)
                username_payload = f"{{RSA}}{encrypted_username}"
                password_payload = f"{{RSA}}{encrypted_password}"
            else:
                print(f"[{self.account_id}] 警告: 未获取到 RSA 公钥，尝试发送明文凭据 (不推荐)。")
                username_payload = self.username
                password_payload = self.password

            login_data = {
                "appKey": "cloud", "accountType": '01',
                "userName": username_payload, "password": password_payload,
                "validateCode": "", "captchaToken": login_params['captchaToken'],
                "returnUrl": login_params['returnUrl'], "mailSuffix": "@189.cn",
                "paramId": login_params['paramId']
            }
            print(f"[{self.account_id}] 正在提交登录凭据...")
            resp_submit = self.session.post(Config.LOGIN_SUBMIT_URL, data=login_data, headers=Config.LOGIN_HEADERS, timeout=15)

            result = resp_submit.json()
            if result.get('result') == 0:
                to_url = result.get('toUrl')
                if to_url:
                    print(f"[{self.account_id}] 登录成功，正在跳转到最终页面...")
                    self.session.get(to_url, timeout=15) # 增加超时时间
                    print(f"[{self.account_id}] 登录流程完成。")
                    return True
                else:
                    print(f"[{self.account_id}] 登录成功但未找到跳转URL。")
                    return False
            else:
                print(f"[{self.account_id}] 登录失败，信息：{result.get('msg')}。")
                return False
        except requests.exceptions.Timeout:
            print(f"[{self.account_id}] 登录请求超时。")
            return False
        except requests.exceptions.RequestException as e:
            print(f"[{self.account_id}] 登录网络请求失败: {e}。")
            return False
        except json.JSONDecodeError:
            print(f"[{self.account_id}] 登录失败：无法解析服务器响应。响应内容: {resp_submit.text[:200]}...")
            return False
        except Exception as e:
            print(f"[{self.account_id}] 登录过程中发生意外错误：{e}。")
            return False

    def sign_in(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        执行每日签到。
        返回 (是否成功, 消息, 原始响应数据或错误信息)
        """
        response_data: Dict[str, Any] = {}
        try:
            # 签到任务内部不再需要额外延迟，延迟在外部提交任务时控制
            # time.sleep(random.uniform(0.1, 0.5))

            rand = str(round(time.time() * 1000))
            sign_url = Config.SIGN_URL_TEMPLATE.format(rand)
            response = self.session.get(sign_url, headers=Config.SIGN_HEADERS, timeout=10) # 增加超时时间

            # 检查HTTP状态码
            if response.status_code != 200:
                return False, f"HTTP错误：状态码 {response.status_code}", {"status_code": response.status_code, "text": response.text[:200]}

            try:
                result = response.json()
                response_data = result
            except json.JSONDecodeError:
                return False, f"签到失败：无法解析服务器响应。响应内容: {response.text[:200]}...", {"raw_response": response.text}

            netdisk_bonus = result.get('netdiskBonus', 0)
            if result.get('isSign'):
                return True, f"已签到，获得{netdisk_bonus}M空间", response_data
            else:
                # 如果 isSign 为 False，尝试从 msg 字段获取具体失败原因
                error_msg = result.get('msg', '未知错误')
                # 某些情况下，可能返回 isSign:false 但没有msg，可以根据业务判断是否为成功
                # 这里我们假设 isSign:false 且有 msg 则为失败
                if error_msg != '未知错误' and error_msg != '已签到': # 排除 '已签到' 这种可能表示成功的消息
                    return False, f"签到失败：{error_msg}", response_data
                else:
                    # 如果 isSign 为 False 但 msg 为空或表示已签到，则认为是成功，或者服务器没有提供明确的成功/失败指示
                    # 这里保持原逻辑：isSign为False时，如果msg不明确指示失败，仍视为成功
                    return True, f"签到成功，获得{netdisk_bonus}M空间", response_data

        except requests.exceptions.Timeout:
            return False, "签到请求超时", {"error": "Timeout"}
        except requests.exceptions.RequestException as e:
            return False, f"签到网络请求失败: {e}", {"error": str(e)}
        except Exception as e:
            return False, f"签到失败: 发生未知异常 {e}", {"error": str(e)}

    def run(self) -> Dict[str, Any]:
        """
        执行完整的登录和并发签到流程。
        登录后，使用多个线程并发执行签到任务，并在提交任务时引入微小延迟。
        """
        results: Dict[str, Any] = {'account_id': self.account_id, 'login': '登录失败', 'sign_in_summary': None}

        print(f"[{self.account_id}] 开始执行...")
        if not self.login():
            print(f"[{self.account_id}] 登录失败，终止后续操作。")
            return results
        results['login'] = '登录成功'
        print(f"[{self.account_id}] 登录成功。")

        sign_in_results_raw: List[Dict[str, Any]] = []
        max_workers = int(os.getenv("MAX_WORKERS", 50)) # 从环境变量获取线程数，默认为50

        print(f"[{self.account_id}] 准备并发执行 {Config.CONCURRENT_SIGN_IN_ATTEMPTS} 次签到任务，使用 {max_workers} 个线程。")

        # 使用线程池并发执行签到
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_run = {}
            for i in range(Config.CONCURRENT_SIGN_IN_ATTEMPTS):
                # 在提交每个任务之前引入一个小的随机延迟
                delay = random.uniform(Config.SUBMIT_DELAY_MIN, Config.SUBMIT_DELAY_MAX)
                time.sleep(delay)
                future = executor.submit(self.sign_in)
                future_to_run[future] = i + 1 # 记录任务编号

            for future in as_completed(future_to_run):
                run_num = future_to_run[future]
                try:
                    success, msg, raw_data = future.result()
                    sign_in_results_raw.append({'success': success, 'message': msg, 'raw_data': raw_data})
                except Exception as exc:
                    sign_in_results_raw.append({'success': False, 'message': f"任务 {run_num} 产生异常: {exc}", 'raw_data': {"error": str(exc)}})

        # 汇总签到结果
        successful_sign_ins = [r for r in sign_in_results_raw if r['success']]
        failed_sign_ins = [r for r in sign_in_results_raw if not r['success']]

        success_count = len(successful_sign_ins)
        failure_count = len(failed_sign_ins)

        # 提取并去重所有返回的消息（只显示成功和明确失败的通用消息）
        unique_messages = sorted(list(set(r['message'] for r in sign_in_results_raw)))

        results['sign_in_summary'] = {
            'total_attempts': Config.CONCURRENT_SIGN_IN_ATTEMPTS,
            'success_count': success_count,
            'failure_count': failure_count,
            'messages': unique_messages,
            'successful_details': successful_sign_ins, # 保留成功签到的详细信息
            'failed_details': failed_sign_ins # 保留失败签到的详细信息
        }
        print(f"[{self.account_id}] 签到任务执行完毕。")
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
    处理单个账户（登录、并发签到）并返回格式化的结果字符串。
    """
    i, (username, password) = account_info
    account_id = f"账户{i} ({username[:3]}***)"
    output = [f"## {account_id}"]

    try:
        bot = TianYiCloudBot(username, password, account_id)
        results = bot.run()

        output.append("### 执行结果")
        output.append(f"- **登录状态**: {results['login']}")

        if results.get('sign_in_summary'):
            summary = results['sign_in_summary']
            output.append("- **并发签到结果**:")
            output.append(f" - **总尝试次数**: {summary['total_attempts']}")
            output.append(f" - ✅ **成功次数**: {summary['success_count']}")
            output.append(f" - ❌ **失败次数**: {summary['failure_count']}")
            output.append(" - **返回信息汇总**:")
            if summary['messages']:
                for msg in summary['messages']:
                    output.append(f"   - {msg}")
            else:
                output.append("   - 未收到任何返回信息。")

            # 打印详细的成功和失败记录 (仅作调试用，生产环境可能过多)
            # output.append("\n#### 成功签到详情:")
            # for detail in summary['successful_details']:
            #     output.append(f" - {detail['message']} (数据: {json.dumps(detail['raw_data'], ensure_ascii=False)})")
            # output.append("\n#### 失败签到详情:")
            # for detail in summary['failed_details']:
            #     output.append(f" - {detail['message']} (数据: {json.dumps(detail['raw_data'], ensure_ascii=False)})")

        else:
            output.append("- 未执行签到操作。")
    except Exception as e:
        output.append(f"### {account_id} 发生意外错误")
        output.append(f"- **错误信息**: {e}")

    return "\n".join(output)

def main():
    """主程序入口。"""
    start_time = datetime.now()
    print("# 天翼云盘自动并发签到程序")
    print()

    accounts = load_accounts_from_env()
    # 从环境变量获取 MAX_WORKERS，默认为 50
    max_workers_env = int(os.getenv("MAX_WORKERS", 50))

    print("## 执行概览")
    print(f"- **启动时间**: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"- **账户数量**: {len(accounts)} 个")
    print(f"- **签到并发任务总数**: {Config.CONCURRENT_SIGN_IN_ATTEMPTS} 次/账户")
    print(f"- **并发线程数 (MAX_WORKERS)**: {max_workers_env}")
    print(f"- **任务提交延迟范围**: {Config.SUBMIT_DELAY_MIN:.2f}-{Config.SUBMIT_DELAY_MAX:.2f} 秒")
    print("-" * 20)

    # 依次处理每个账户
    # 如果账户数量很多，可以考虑在这里引入 ThreadPoolExecutor 来并发处理多个账户
    for i, (username, password) in enumerate(accounts, 1):
        account_info = (i, (username, password))
        result_str = process_account(account_info)
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

