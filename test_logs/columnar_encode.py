#!/usr/bin/env python3
"""
Columnar encoding: separate log fields into columns, compress each.
For Apache CLF logs: IP, ident, user, timestamp, request, status, size
"""
import re
import sys

# Apache Combined Log Format regex
CLF_PATTERN = re.compile(
    r'^(\S+)\s+'           # IP/host
    r'(\S+)\s+'            # ident
    r'(\S+)\s+'            # user
    r'\[([^\]]+)\]\s+'     # timestamp
    r'"([^"]*)"\s+'        # request
    r'(\d+)\s+'            # status
    r'(\S+)'               # size
)

def parse_clf(lines):
    ips, timestamps, methods, paths, statuses, sizes = [], [], [], [], [], []
    unparsed = []
    
    for line in lines:
        m = CLF_PATTERN.match(line)
        if m:
            ip, ident, user, ts, request, status, size = m.groups()
            ips.append(ip)
            timestamps.append(ts)
            
            # Parse request
            parts = request.split(' ', 2)
            if len(parts) >= 2:
                methods.append(parts[0])
                paths.append(parts[1])
            else:
                methods.append(request)
                paths.append('')
            
            statuses.append(status)
            sizes.append(size)
        else:
            unparsed.append(line)
    
    return {
        'ips': ips,
        'timestamps': timestamps, 
        'methods': methods,
        'paths': paths,
        'statuses': statuses,
        'sizes': sizes,
        'unparsed': unparsed
    }

def main():
    input_file = sys.argv[1]
    
    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]
    
    cols = parse_clf(lines)
    
    print(f"Parsed {len(cols['ips'])} lines, {len(cols['unparsed'])} unparsed")
    
    # Write each column
    for name, data in cols.items():
        with open(f"{input_file}.col_{name}", 'w') as f:
            f.write('\n'.join(data))
        print(f"  {name}: {len(data)} items")

if __name__ == '__main__':
    main()
