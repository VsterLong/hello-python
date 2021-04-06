#!/usr/bin/env python

###
# Author: LongZhx
# Date: 2021-04-06
# Function: Win10 Nat Config
###

import socket
import os
import time

del_cmd = "netsh interface portproxy delete v4tov4 listenaddress={} listenport={}"
show_cmd = "netsh interface portproxy show v4tov4"
add_cmd = "netsh interface portproxy add v4tov4 listenaddress={} listenport={} connectaddress={} connectport={}"


def get_hostip_byname() -> str:
    try:
        name = socket.gethostname()
        ip = socket.gethostbyname(name)
        return ip
    except:
        return None


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


def loop_start():
    while True:
        time.sleep(0.5)
        print("\n########### NAT ##############")
        print("# 1: 删除NAT设置             #")
        print("# 2: 显示NAT设置             #")
        print("# 3: 新增NAT配置             #")
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
            elif num == 0:
                exit(0)
            else:
                print("不在指定操作内！")
        except:
            print("输入错误！")


if __name__ == "__main__":
    loop_start()
