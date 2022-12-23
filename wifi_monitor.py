import subprocess
import time
import os

timestr = str(time.strftime("%Y-%m-%d_%H:%M:%S"))
print(timestr)
#Need to change Folder Path below
subprocess.call("tshark -i en0 -I -b duration:30 -w /Folder/Path/wifi.pcapng", shell=True)