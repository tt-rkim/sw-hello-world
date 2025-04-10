from concurrent.futures import ProcessPoolExecutor
import regex as re
import subprocess
import argparse

RETRAIN_COUNT_ADDR = "1EDC"
ETH_STATUS_ADDR = "1200"
ROUTER_SYNC_ADDR = "ECF0"
ROUTER_STATUS_ADDR = "39000"

NUM_PORTS = 16

ROUTER_SYNC_DONE = '0xaa'

ROUTER_STATUS_STARTED = '0xabc00000'
ROUTER_STATUS_TIMEOUT = '0xabcdead0'
ROUTER_STATUS_PASS = '0xabc00001'

def read_from_eth_core(port, address, num_words, device):
    command_str = "./read-noc --eth_id {p} --addr 0x{addr} --num_words {n} --interface pci:{d}"
    command = command_str.format(p=port,
                                 addr=address,
                                 n=num_words,
                                 d=device)
    try:
        result = subprocess.check_output(command, shell=True).decode("utf-8")
    except subprocess.CalledProcessError as e:
        result = None

    return result

def parse_hex_from_output(data):
    output_patt = r"([0-9]+: 0x[0-f]+ => 0x)([0-f]+)"
    match = re.search(output_patt, data)
    if match:
        return match.group(2)
    else:
        return None

def parse_eth_status_data(data):
    device_status = {}
    device_status["ETH_UNKNOWN"] = []
    device_status["ETH_UNCONNECTED"] = []
    device_status["ETH_CONNECTED"] = []
    device_status["READ_ERROR"] = []
    if data == None:
        return device_status
    data = data.splitlines()
    for i in range(len(data)):
        port_status = parse_hex_from_output(data[i])
        if port_status:
            status_val = int(port_status)
            if status_val == 0:
                status_str = "ETH_UNKNOWN"
            elif status_val == 1:
                status_str = "ETH_UNCONNECTED"
            else:
                status_str = "ETH_CONNECTED"
        else:
            status_str = "READ_ERROR"

        device_status[status_str].append(i)
    return device_status

def log_device_data_generic(device_id, data):
    # log format, expects data to be dict
    output_str = "Device: {d} ".format(d=device_id)
    for key in data:
        output_str += "{k}: {l} (Total: {s}) ".format(k=key, l=data[key], s=len(data[key]))
    print(output_str)

def log_device_retrain_count_data(device_id, data):
    output_str = "Device: {d} ".format(d=device_id)
    for key in data:
        output_str += "[{k}: {v}] ".format(k=key, v=data[key])
    print(output_str)

def collect_device_eth_status(device_id):
    raw_status = read_from_eth_core(0, ETH_STATUS_ADDR, NUM_PORTS, device_id)
    device_stats = parse_eth_status_data(raw_status)
    return device_stats

def collect_device_retrain_count(device_id):
    device_stats = {}
    for port_id in range(0, NUM_PORTS):
        raw_data = read_from_eth_core(port_id, RETRAIN_COUNT_ADDR, 1, device_id)
        retrain_count_hex = parse_hex_from_output(raw_data)
        if retrain_count_hex:
            retrain_count = int(retrain_count_hex, 16)
            device_stats[port_id] = retrain_count
    return device_stats

def parse_router_sync_data(data):
    data = data.splitlines()
    sync_in = hex(int(parse_hex_from_output(data[0]), 16))
    sync_out = hex(int(parse_hex_from_output(data[4]), 16))
    return (sync_in == ROUTER_SYNC_DONE) or (sync_out == ROUTER_SYNC_DONE)

def collect_device_router_sync(device_id):
    device_stats = {}
    device_stats["DONE"] = []
    device_stats["PENDING"] = []
    for port_id in range(0, NUM_PORTS):
        raw_data = read_from_eth_core(port_id, ROUTER_SYNC_ADDR, 8, device_id)
        sync_done = parse_router_sync_data(raw_data)
        if sync_done:
            device_stats["DONE"].append(port_id)
        else:
            device_stats["PENDING"].append(port_id)
    return device_stats

def collect_device_router_status(device_id):
    device_stats = {}
    device_stats["STARTED"] = []
    device_stats["TIMED_OUT"] = []
    device_stats["PASS"] = []
    device_stats["OTHER"] = []
    for port_id in range(0, NUM_PORTS):
        raw_data = read_from_eth_core(port_id, ROUTER_STATUS_ADDR, 1, device_id)
        router_status = hex(int(parse_hex_from_output(raw_data), 16))
        if router_status == ROUTER_STATUS_STARTED:
            status_str = "STARTED"
        elif router_status == ROUTER_STATUS_TIMEOUT:
            status_str = "TIMED_OUT"
        elif router_status == ROUTER_STATUS_PASS:
            status_str = "PASS"
        else:
            status_str = "OTHER"
        device_stats[status_str].append(port_id)
    return device_stats


if __name__ == "__main__":
    executor = ProcessPoolExecutor()

    parser = argparse.ArgumentParser()
    parser.add_argument('--retrain_count', action='store_true')
    parser.add_argument('--router_sync', action='store_true')
    parser.add_argument('--router_status', action='store_true')
    parser.add_argument('--device_id', default=-1)

    args = parser.parse_args()
    device_id = args.device_id

    devices = []
    results = []
    if device_id == -1:
        devices = range(0, 32)
    else:
        devices = [device_id]

    if args.retrain_count:
        results = executor.map(collect_device_retrain_count, devices)
    elif args.router_sync:
        results = executor.map(collect_device_router_sync, devices)
    elif args.router_status:
        results = executor.map(collect_device_router_status, devices)
    else:
        results = executor.map(collect_device_eth_status, devices)

    results = list(results)

    for i in range(len(results)):
        if args.retrain_count:
            log_device_retrain_count_data(devices[i], results[i])
        else:
            log_device_data_generic(devices[i], results[i])
