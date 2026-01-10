import random
import sys

n = int(sys.argv[1])
levels = ["INFO", "WARN", "ERROR", "DEBUG"]
components = ["DataNode", "NameNode", "FSNamesystem", "BlockManager", "PacketResponder"]
actions = ["received", "sent", "terminated", "added", "removed", "updated", "started", "completed"]

for i in range(n):
    ts = f"2024{random.randint(1,12):02d}{random.randint(1,28):02d} {random.randint(0,23):02d}{random.randint(0,59):02d}{random.randint(0,59):02d}"
    pid = random.randint(1, 999)
    level = random.choice(levels)
    comp = random.choice(components)
    blk = f"blk_{random.randint(-9999999999999999999, 9999999999999999999)}"
    action = random.choice(actions)
    ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}:50010"
    print(f"{ts} {pid} {level} dfs.{comp}: {action} block {blk} from {ip}")
