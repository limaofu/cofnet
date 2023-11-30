#!/usr/bin/env python3
# coding=utf-8
# author: Cof-Lee
# update: 2023-11-30
# module name: cofnet
# 本模块使用cof-lee开源协议 v1.0
# 所有条款及内容如下：
# （1）无担保：作者不保证源代码内容的准确无误，亦不承担由于使用此源代码所导致的任何后果
# （2）自由使用：任何人可以出于任何目的而自由地 阅读/链接/打印/转载/引用/分发/再创作 此源代码，无需任何附加条件

"""
术语解析:
maskint    掩码数字型 ，如 24 ，子网掩码位数，          类型: int
maskbyte   掩码字节型 ，如 255.255.255.0 ，子网掩码，  类型: str
ip         ip地址称，如 10.1.1.2 ，不含掩码           类型: str
netseg     网段，如 10.1.0.0 ，不含掩码               类型: str
cidr       地址块，网段及掩码位数 ，如 10.1.0.0/16        类型: str
"""


def is_ip_addr(input_str):
    # 判断 输入字符串 是否为 ip地址，返回bool值，是则返回True，否则返回False
    # input <str> , output <bool>
    seg_list = input_str.split(".")
    if len(seg_list) != 4:
        return False
    if seg_list[0].isdigit():
        if 0 > int(seg_list[0]) or int(seg_list[0]) > 255:
            return False
    if seg_list[1].isdigit():
        if 0 > int(seg_list[1]) or int(seg_list[1]) > 255:
            return False
    if seg_list[2].isdigit():
        if 0 > int(seg_list[2]) or int(seg_list[2]) > 255:
            return False
    if seg_list[3].isdigit():
        if 0 > int(seg_list[3]) or int(seg_list[3]) > 255:
            return False
        else:
            return True
    else:
        return False


def is_cidr(input_str):
    # 判断 输入字符串 是否为 cidr地址块，返回bool值，是则返回True，否则返回False
    # 输入 "10.99.1.0/24" 输出 True
    # 输入 "10.99.1.1/24" 输出 False ，不是正确的cidr地址块写法，24位掩码，的最后一字节必须为0
    # input <str> , output <bool>
    seg_list = input_str.split(".")
    if len(seg_list) != 4:
        return False
    if seg_list[0].isdigit():
        if 0 > int(seg_list[0]) or int(seg_list[0]) > 255:
            return False
    if seg_list[1].isdigit():
        if 0 > int(seg_list[1]) or int(seg_list[1]) > 255:
            return False
    if seg_list[2].isdigit():
        if 0 > int(seg_list[2]) or int(seg_list[2]) > 255:
            return False
    if seg_list[3].isdigit():
        return False
    seg_list2 = seg_list[3].split("/")
    if len(seg_list2) == 2:
        if seg_list2[1].isdigit():
            if 0 > int(seg_list2[1]) or int(seg_list2[1]) > 32:
                return False
    else:
        return False
    seg_list3 = input_str.split("/")
    seg_list4 = seg_list3[0].split(".")
    ip_mask_int = int(seg_list4[0]) << 24 | int(seg_list4[1]) << 16 | int(seg_list4[2]) << 8 | int(seg_list4[3])
    ip_mask_int_and = ip_mask_int & (0xFFFFFFFF << (32 - int(seg_list3[1])))
    if ip_mask_int != ip_mask_int_and:
        return False
    return True


def is_ip_range(input_str):
    # 判断 输入字符串 是否为 ip地址范围，返回bool值，是则返回True，否则返回False
    # 输入 "10.99.1.33-55" 输出 True
    # 输入 "10.99.1.22-10" 输出 False ，不是正确的地址范围，首ip大于了尾ip
    # input <str> , output <bool>
    seg_list = input_str.split(".")
    if len(seg_list) != 4:
        return False
    if seg_list[0].isdigit():
        if 0 > int(seg_list[0]) or int(seg_list[0]) > 255:
            return False
    if seg_list[1].isdigit():
        if 0 > int(seg_list[1]) or int(seg_list[1]) > 255:
            return False
    if seg_list[2].isdigit():
        if 0 > int(seg_list[2]) or int(seg_list[2]) > 255:
            return False
    if seg_list[3].isdigit():
        return False
    seg_list2 = seg_list[3].split("-")
    if len(seg_list2) == 2:
        if seg_list2[0].isdigit():
            if 0 > int(seg_list2[0]) or int(seg_list2[0]) > 255:
                return False
        if seg_list2[1].isdigit():
            if 0 > int(seg_list2[1]) or int(seg_list2[1]) > 255:
                return False
        if int(seg_list2[0]) >= int(seg_list2[1]):
            return False
        return True
    else:
        return False


def maskint_to_maskbyte(maskint):
    # 将子网掩码数字型 转为 子网掩码字节型，例如：
    # 输入 16 输出 "255.255.0.0"
    # 输入 24 输出 "255.255.255.0"
    # input <int> , output <str>
    if maskint < 0 or maskint > 32:
        raise Exception("子网掩码数值应在[0-32]", maskint)
    mask = [0, 0, 0, 0]
    i = 0
    while maskint >= 8:
        mask[i] = 255
        i += 1
        maskint -= 8
    if i < 4:
        mask[i] = 255 - (2 ** (8 - maskint) - 1)
    mask_str_list = map(str, mask)
    return ".".join(mask_str_list)


def local_mask_seg_to_cidr(mask_seg):
    # 将掩码其中一个字节的数字 转为 二进制数最开头的1的个数, 例如：
    # 输入 "192" 输出 2 ，即 1100 0000
    # 输入 "248" 输出 5 ，即 1111 1000
    # 输入 "255" 输出 8 ，即 1111 1111
    # input <str> , output <int>
    mask_seg_1_number = 0
    mask_seg_int = int(mask_seg)
    while mask_seg_int != 0:
        mask_seg_1_number += 1
        mask_seg_int = (mask_seg_int << 1) & 0xFF
    return mask_seg_1_number


def maskbyte_to_maskint(maskbyte):
    # 将子网掩码字节型 转为 子网掩码数字型，例如：
    # 输入 "255.255.255.0" 输出 24
    # 输入 "255.255.0.0"   输出 16
    # input <str> , output <int>
    if not is_ip_addr(maskbyte):
        raise Exception("不是正确的子网掩码,E1", maskbyte)
    mask_seg_list = maskbyte.split(".")
    mask_seg_index = 0
    maskint = 0
    while mask_seg_list[mask_seg_index] == "255":
        maskint += 8
        mask_seg_index += 1
        if mask_seg_index == 4:
            break
    if mask_seg_index < 4 and mask_seg_list[mask_seg_index] != "":
        maskint += local_mask_seg_to_cidr(mask_seg_list[mask_seg_index])  # 依赖上面的 local_mask_seg_to_cidr()
    if maskbyte != maskint_to_maskbyte(maskint):
        raise Exception("不是正确的子网掩码,E2", maskbyte)
    return maskint


def ip_mask_to_int(ip_or_mask):
    # 将 ip地址或掩码byte型 转为 32 bit的数值，例如：
    # 输入 "255.255.255.0" 输出 4294967040
    # 输入 "192.168.1.1"   输出 3232235777
    # input <str> , output <int>
    if not is_ip_addr(ip_or_mask):
        raise Exception("不是正确的ip地址或掩码", ip_or_mask)
    seg_list = ip_or_mask.split(".")
    ip_mask_int = int(seg_list[0]) << 24 | int(seg_list[1]) << 16 | int(seg_list[2]) << 8 | int(seg_list[3])
    return ip_mask_int


def int32_to_ip(int32):
    # 将 32bit数值 转为 ipv4地址，例如:
    # 输入 174260481 输出 "10.99.1.1"
    # input <int> , output <str>
    if int32 < 0 or int32 > 4294967295:
        raise Exception("ip地址数值应在[0-4294967295]", int32)
    ipaddress = [0, 0, 0, 0]
    ipaddress[0] = 0xFF & (int32 >> 24)
    ipaddress[1] = 0xFF & (int32 >> 16)
    ipaddress[2] = 0xFF & (int32 >> 8)
    ipaddress[3] = 0xFF & int32
    ipaddress_str_list = map(str, ipaddress)
    return ".".join(ipaddress_str_list)


def get_netseg_int(ip, maskintorbyte):
    # 根据 子网掩码 获 取ip地址的 网段（int值），子网掩码可为int型或byte型，例如：
    # 输入 "10.99.1.1","24"             输出 174260480
    # 输入 "10.99.1.1","255.255.255.0"  输出 174260480
    # input <str,int/str> , output <int>
    if not is_ip_addr(ip):
        raise Exception("不是正确的ip地址,E1", ip)
    maskintorbyte_seg = str(maskintorbyte).split(".")
    if len(maskintorbyte_seg) == 1:
        if int(maskintorbyte_seg[0]) < 0 or int(maskintorbyte_seg[0]) > 32:
            raise Exception("子网掩码数值应在[0-32]", maskintorbyte_seg)
        else:
            maskint2bin = 0xFFFFFFFF << (32 - int(maskintorbyte_seg[0]))
            return ip_mask_to_int(ip) & maskint2bin
    if len(maskintorbyte_seg) == 4:
        if not is_ip_addr(maskintorbyte):
            raise Exception("不是正确的掩码,E2", maskintorbyte)
        maskint2bin = 0xFFFFFFFF << (32 - int(maskbyte_to_maskint(maskintorbyte)))
        return ip_mask_to_int(ip) & maskint2bin
    else:
        raise Exception("不是正确的掩码,E3", maskintorbyte)


def get_netseg_byte(ip, maskintorbyte):
    # 根据 子网掩码 获 取ip地址的 网段（byte值），子网掩码可为int型或byte型，例如：
    # 输入 "10.99.1.1","24"             输出 10.99.1.0
    # 输入 "10.99.1.1","255.255.255.0"  输出 10.99.1.0
    # 依赖上面的2个函数:  get_netseg_int() 以及 int32_to_ip()
    # input <str,int/str> , output <str>
    return int32_to_ip(get_netseg_int(ip, maskintorbyte))


def is_ip_in_cidr(ip, cidr):
    # 判断 ip地址 是否在 网段cidr内，此ip是否属于某网段地址块，返回bool值: True表示ip在网段内，False不在网段内
    # 输入 "10.99.1.1","10.99.1.0/24"  输出 True
    # 输入 "10.99.3.1","10.99.1.0/24"  输出 False
    # input <str, str> , output <bool>
    if not is_ip_addr(ip):
        raise Exception("不是正确的ip地址,E1", ip)
    if not is_cidr(cidr):
        raise Exception("不是正确的cidr地址块,E2", cidr)
    netseg_maskint = cidr.split("/")
    netseg = netseg_maskint[0]
    maskint = netseg_maskint[1]
    ipnetsegint = get_netseg_int(ip, maskint)
    netsegint = get_netseg_int(netseg, maskint)
    if ipnetsegint == netsegint:
        return True
    else:
        return False


def is_ip_in_net_maskbyte(ip, net, maskbyte):
    # 判断 ip地址 是否在 网段 net maskbyte内，是否属于某网段地址块，返回bool值: True表示ip在网段内，False不在网段内
    # 输入 "10.99.1.1","10.99.1.0","255.255.255.0"  输出 True
    # 输入 "10.99.3.1","10.99.1.0","255.255.255.0"  输出 False
    # input <str, str, str> , output <bool>
    if not is_ip_addr(ip):
        raise Exception("不是正确的ip地址,E1", ip)
    if not is_ip_addr(net):
        raise Exception("不是正确的网段,E2", net)
    if not is_ip_addr(maskbyte):
        raise Exception("不是正确的掩码,E3", maskbyte)
    ipnetsegint = get_netseg_int(ip, maskbyte)
    netsegint = get_netseg_int(net, maskbyte)
    if ipnetsegint == netsegint:
        return True
    else:
        return False


def is_ip_in_range(targetip, start_ip, end_ip):
    # 判断 ip地址 是否在 ip地址范围内，返回bool值: True表示ip在ip-range内，False不在ip-range内
    # 输入 "10.99.1.88","10.99.1.1","10.99.2.22"  输出 True
    # 输入 "10.99.1.88","10.99.1.1","10.99.1.22"  输出 False
    # input <str, str, str> , output <bool>
    if not is_ip_addr(targetip):
        raise Exception("不是正确的ip地址,E1", targetip)
    if not is_ip_addr(start_ip):
        raise Exception("不是正确的ip地址,E2", start_ip)
    if not is_ip_addr(end_ip):
        raise Exception("不是正确的ip地址,E3", end_ip)
    if ip_mask_to_int(end_ip) >= ip_mask_to_int(targetip) >= ip_mask_to_int(start_ip):
        return True
    else:
        return False


# #################################  end of module's function  ##############################

if __name__ == '__main__':
    print("this is cofnet.py")
