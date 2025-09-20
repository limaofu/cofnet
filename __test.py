import time
import random
import cofnet3 as cofnet

if __name__ == '__main__':
    print(f"version: {cofnet.version}  requires_python: {cofnet.requires_python}")
    print("generate_ip_list_by_ip_range: ", cofnet.generate_ip_list_by_ip_range("10.99.1.8-12"))
    print("generate_ip_list_by_ip_range_2: ", cofnet.generate_ip_list_by_ip_range_2("10.99.1.8-10.99.1.12"))
    print("is_maskbyte: ", cofnet.is_maskbyte("255.255.254.0"))
    print("maskbyte_to_maskint: ", cofnet.maskbyte_to_maskint("255.255.254.0"))
    print("ip_to_hex_string: ", cofnet.ip_to_hex_string("0.0.1.2"))
    print("get_maskint_with_space: ", cofnet.get_maskint_with_space(9))
    print("ip_to_net_system_id: ", cofnet.ip_to_net_system_id("10.3.1.2"))

    ip_int_list = [random.randint(0, 0xFFFFFFFF) for _ in range(1000000)]
    start_time = time.time()
    for ip_int in ip_int_list:  # 100万个ip的计算量，用时如下：
        ip_address = cofnet.int32_to_ip(ip_int)  # 约 1.0 秒
        #
        try:
            pass
            # cofnet.maskint_to_maskbyte(ip_address) # 2.7 秒
            # cofnet.maskint_to_wildcard_mask(ip_int) # 0.28 秒
            # cofnet.maskbyte_to_maskint(ip_address)  # 4.8 秒
            # cofnet.ip_to_hex_string(ip_address)  # 1.0 秒
            # cofnet.ip_or_maskbyte_to_binary_with_space(ip_address)  # 3.2 秒
            # cofnet.get_maskint_with_space(ip_int)  # 0.3 秒
            # cofnet.get_netseg_int(ip_address, ip_int)  # maskbyte: 3.9,  maskint: 2.0
            # cofnet.get_netseg_byte(ip_address, ip_int)  # maskbyte: 4.1,  maskint: 2.2
            # cofnet.get_netseg_byte_c(ip_address + "/15")  # 2.5 秒
            # cofnet.get_hostseg_int(ip_address,"18")  # 2.4 秒
            # cofnet.get_hostseg_num(ip_int)  # 0.28 秒
            # cofnet.is_ip_in_cidr(ip_address,"128.0.0.0/1") # 7.6 秒
            # cofnet.is_ip_in_net_maskbyte(ip_address, "128.0.0.0", "128.0.0.0")  # 24.6 秒
            # cofnet.is_ip_in_range(ip_address,"10.99.1.1-255")  # 0.70 秒
            # cofnet.generate_ip_list_by_ip_range(ip_address + "-128")  # 44.5 秒
            # ip_address2 = cofnet.int32_to_ip(ip_int+64)  # 约 1.0 秒  （这行和下面一行是一起的）
            # cofnet.generate_ip_list_by_ip_range_2(ip_address+"-"+ip_address2)  # 74.0 秒  （这行和上面一行是一起的）
            # system_id = cofnet.ip_to_net_system_id(ip_address)  # 约3.2秒
        except Exception:
            pass
        # print(ip_int)
        # ip_intxx = cofnet.ip_or_maskbyte_to_int(ip_address)  # 约 0.8 秒
        # cofnet.is_maskbyte(ip_address)  # 2.2 秒
        # cofnet.is_ip_range_2(ip_address+"-128.128.128.128") # 3.8 秒
        # cofnet.is_ip_range(ip_address+"-128") # 1.7 秒
        # cofnet.is_ip_with_maskint(ip_address + "/23")  # 1.6 秒
        # cofnet.is_netseg_with_maskbyte(ip_address,"255.255.254.0") # 12.3 秒
        # cofnet.is_cidr(ip_address+"/23") # 2.3 秒
        # cofnet.is_ip_addr(ip_address)  # 1.2 秒
        # cofnet.is_ipv6_addr("FC00:DC02:10:99::2a")  # 4.3 秒
        # cofnet.is_ipv6_with_prefix_len("FC00:DC02:10:99::2a/64")  # 4.6 秒
        # cofnet.convert_to_ipv6_full("FC00:C02:10::2a")  # 5.5 秒
        # cofnet.convert_to_ipv6_short("FD00:0123:0000:0000:033:0000:0000:0011")  # 19.7 秒
        # cofnet.get_ipv6_prefix("FD00:0000:0000:0000:00a0:0000:0000:8811", 80)  # 34.2 秒
        # cofnet.get_ipv6_prefix_cidrv6("FD00:0000:0000:0000:000A:0000:0000:8811", 80)  # 36.2 秒
        #############################################################
    print(f"用时： {time.time() - start_time} 秒")
