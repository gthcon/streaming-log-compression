import json
import random
import time

levels = ["INFO", "WARN", "ERROR", "DEBUG"]
services = ["api-gateway", "user-service", "order-service", "payment-service", "inventory-service"]
actions = ["request_received", "processing", "db_query", "cache_hit", "cache_miss", "response_sent", "error_occurred"]

for i in range(100000):
    log = {
        "timestamp": f"2024-01-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(0,999):03d}Z",
        "level": random.choice(levels),
        "service": random.choice(services),
        "action": random.choice(actions),
        "request_id": f"req-{random.randint(10000000, 99999999)}",
        "user_id": f"user-{random.randint(1000, 9999)}",
        "duration_ms": random.randint(1, 5000),
        "message": f"Processing request for endpoint /api/v1/{random.choice(['users', 'orders', 'products', 'payments'])}/{random.randint(1, 10000)}"
    }
    print(json.dumps(log))
