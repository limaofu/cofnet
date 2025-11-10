import time
import cofping

target_ip = "223.5.5.5"
detect_interval = 2  # 超时时间，单位：秒
log_file_name = "ping_log.txt"

while True:
    ping_obj = cofping.PingOnePacket(target_ip=target_ip, timeout=2, size=400, ttl=128, dont_frag=True)
    start_time = time.time()
    ping_obj.start()
    result = ping_obj.result
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if result.is_success:
        log_content = f"{current_time} success, from: {result.respond_source_ip} size={result.size} TTL={result.ttl} rtt={result.rtt_ms} ms\n"
    else:
        log_content = f"{current_time} failed, {result.failed_info}\n"
    print(log_content)
    with open(log_file_name, 'a') as f:  # 将日志输出到文件里
        f.write(log_content)
    using_time = time.time() - start_time
    if detect_interval > using_time:
        wait_time = detect_interval - using_time
        time.sleep(wait_time)
