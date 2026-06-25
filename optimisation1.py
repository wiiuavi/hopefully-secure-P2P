#packet = struct.pack('!BHHB', 0x05, payload_len, instance_id, str_len) + encoded_name

import socket
import struct
import os
import shutil
import threading

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)


def task_clone_map(instanceID, map_template_name):
    print(f"[Async worker] Task: clone map {map_template_name} for instance {instanceID}")
    sourceDir = f"./templates/{map_template_name}"
    instanceFolder = f"./instances/{instanceID}"
    taskStatus = 0x01
    if os.path.exists(sourceDir):
        shutil.copytree(sourceDir, instanceFolder, dirs_exist_ok=True) # ensure that any existing map files are overwritten
    else:
        taskStatus = 0x00
        print(f"[Async worker] Failed Task: clone map {map_template_name} for instance {instanceID}\n       {map_template_name} doesn't exist")
    return struct.pack("!BHHe", 0x06, 3, instanceID, taskStatus)

def task_del_map(instanceID):
    print(f"[Async worker] Task: del map for instanceID {instanceID}")
    sourceDir = f"./instances/{instanceID}"
    taskStatus = 0x01
    if os.path.exists(sourceDir):
        shutil.rmtree(sourceDir)
    else:
        print(f"[Async worker] Failed Task: del map for instance {instanceID}\n     {instanceID} doesn't exist.")
        taskStatus = 0x00
    return struct.pack('!BHHB', 0x07, 3, instanceID, taskStatus)

