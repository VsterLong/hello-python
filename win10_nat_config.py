#!/usr/bin/env python

###
# Author: LongZhx
# Date: 2021-04-06
# Function: Win10 Nat Config
###

import socket
import os
import time
import os
from glob import glob
import subprocess as sp

del_cmd = "netsh interface portproxy delete v4tov4 listenaddress={} listenport={}"
show_cmd = "netsh interface portproxy show v4tov4"
add_cmd = "netsh interface portproxy add v4tov4 listenaddress={} listenport={} connectaddress={} connectport={}"

cmd_select_proxy = 'Get-ItemProperty -Path "Registry::HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"'
cmd_disable_proxy = 'Set-ItemProperty -Path "Registry::HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ProxyEnable -value \'{}\''
cmd_set_proxy = 'Set-ItemProperty -Path "Registry::HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ProxyServer -value \'{}\''


class PowerShell():
    def __init__(self, coding):
        # Do not print headers
        cmd = [self._where('PowerShell.exe'), "-NoLogo", "-NonInteractive",
               "-Command", "-"]
        startupinfo = sp.STARTUPINFO()
        startupinfo.dwFlags |= sp.STARTF_USESHOWWINDOW
        self.popen = sp.Popen(cmd, stdout=sp.PIPE, stdin=sp.PIPE,
                              stderr=sp.STDOUT, startupinfo=startupinfo)
        self.coding = coding

    def __enter__(self):
        return self

    def __exit__(self, a, b, c):
        self.popen.kill()

    def run(self, cmd, timeout=15):
        b_cmd = cmd.encode(encoding=self.coding)
        try:
            b_outs, errs = self.popen.communicate(b_cmd, timeout=timeout)
        except sp.TimeoutExpired:
            self.popen.kill()
            b_outs, errs = self.popen.communicate()
        outs = b_outs.decode(encoding=self.coding)
        return outs, errs

    @ staticmethod
    def _where(filename, dirs=None, env="PATH"):
        """Find file in current dir, in deep_lookup cache or in system path"""
        if dirs is None:
            dirs = []
        if not isinstance(dirs, list):
            dirs = [dirs]
        if glob(filename):
            return filename
        paths = [os.curdir] + os.environ[env].split(os.path.pathsep) + dirs
        try:
            return next(os.path.normpath(match)
                        for path in paths
                        for match in glob(os.path.join(path, filename))
                        if match)
        except (StopIteration, RuntimeError):
            raise IOError("File not found: %s" % filename)


def get_hostip_byname() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        return ip
    except:
        return "127.0.0.1"


def show_nat():
    stdout = os.popen(show_cmd).read()
    stdout = stdout.split('\n')
    stdout = filter(lambda x: x is not None and len(x) != 0, stdout)
    stdout = list(map(lambda x: x.strip(), stdout))
    if len(stdout) < 3:
        return []

    result = stdout[3:]
    result = map(lambda x: x.split(' '), result)
    result = map(lambda x: list(filter(lambda y: y != '', x)), result)
    return list(result)


def add_nat(src_ip, src_port, dst_ip, dst_port):
    nat_old = show_nat()
    if len(nat_old) != 0:
        check_nat = list(
            filter(lambda x: src_ip in x and src_port in x, nat_old))
        if len(check_nat) != 0:
            yes_or_no = input(
                "已存在代理: {}:{}，是否删除？(y)：".format(nat_old[0], nat_old[1]))
            if yes_or_no == 'y':
                return_code = os.popen(del_cmd.format(nat_old[0], nat_old[1]))
                print("删除完成：" + return_code.read().strip())
            else:
                print("不执行任何操作！")
                return

    stdout = os.popen(add_cmd.format(
        src_ip, src_port, dst_ip, dst_port)).read()
    print("Nat 添加完成，" + stdout, end=":")
    print(show_nat())


def delete_nat():
    src_ip = input("输入出源地址：")
    src_port = input("请输入源端口：")
    return_code = os.popen(del_cmd.format(src_ip, int(src_port)))

    print("删除完成：" + return_code.read().strip())


def select_proxy():
    with PowerShell("GBK") as ps:
        outs, err = ps.run(cmd_select_proxy)
        if err is not None:
            print(err)
            return

    outs = outs.split('\r\n')
    proxy_addr = outs[14].split(':', 1)
    proxy_isenable = list(filter(lambda x: x.strip(), outs[10].split(':', 1)))
    is_enbale = "否"
    if proxy_isenable[1].strip() == '1':
        is_enbale = "是"
    print("代理地址：{}，\n代理是否启用：{}".format(proxy_addr[1], is_enbale))


def set_proxy(proxy_url):
    with PowerShell("GBK") as p:
        _, err = p.run(cmd_set_proxy.format(proxy_url))
        if err is not None:
            return
    with PowerShell("GBK") as p:
        _, err = p.run(cmd_disable_proxy.format("1"))
        if err is not None:
            return
    print("代理设置完成并启用：{}。".format(proxy_url))


def disable_proxy():
    with PowerShell("GBK") as p:
        # print(cmd_set_proxy.format(""))
        outs, err = p.run(cmd_set_proxy.format(""))
        # print(outs)
        if err is not None:
            return

    with PowerShell("GBK") as p:
        # print(cmd_disable_proxy.format("0"))
        outs, err = p.run(cmd_disable_proxy.format("0"))
        # print(outs)
        if err is not None:
            return
    print("取消代理完成。")


def loop_start():
    while True:
        time.sleep(0.5)
        print("\n########### NAT ##############")
        print("# 1: 删除NAT设置             #")
        print("# 2: 显示NAT设置             #")
        print("# 3: 新增NAT配置             #")
        print("# 4: 显示本机IP              #")
        print("# 5: 添加代理并启用          #")
        print("# 6: 停用代理服务器          #")
        print("# 7: 查看代理服务器          #")
        print("# q: Quit.                   #")
        print("########### NAT ##############\n")

        number = input("请选择：")

        if number == 'q':
            exit(0)

        try:
            num = int(number)
            if num == 1:
                delete_nat()
            elif num == 2:
                nats = show_nat()
                for nat in nats:
                    print(nat)
            elif num == 3:
                try:
                    sp = int(input("请输入源端口："))
                    dp = int(input("请输入目的端口："))
                    if sp >= 65535 or sp <= 0 or dp >= 65535 or dp <= 0:
                        print("无效端口。")
                        continue

                    add_nat(get_hostip_byname(), sp, "127.0.0.1", dp)
                except Exception as e:
                    print("输入错误：" + str(e))
            elif num == 4:
                print(get_hostip_byname())
            elif num == 5:
                addr = input("请输入代理地址(http://127.0.0.1:65515)：")
                if addr is None or len(addr.strip()) == 0:
                    print("地址错误。")
                    continue

                if "http" not in addr:
                    print("协议错误。")
                    continue

                set_proxy(addr)
            elif num == 6:
                disable_proxy()
            elif num == 0:
                print("Easter Eggs!")
            elif num == 7:
                select_proxy()
            else:
                print("不在指定操作内！")
        except Exception as e:
            print(e)
            print("输入错误！")


if __name__ == "__main__":
    loop_start()
