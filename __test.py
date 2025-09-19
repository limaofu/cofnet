import time
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
    start_time = time.time()
    for ip_int in range(1000000):  # 100万个ip的计算量，用时约 6.9 秒
        ip_address = cofnet.int32_to_ip(ip_int)  # 约 0.93 秒
        cofnet.ip_to_hex_string(ip_address)  # 约2.9秒
        system_id = cofnet.ip_to_net_system_id(ip_address)  # 约3.1秒
    print(f"用时： {time.time() - start_time} 秒")
