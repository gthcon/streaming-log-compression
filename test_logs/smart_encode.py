#!/usr/bin/env python3
"""
Smart encoding: use format-specific parsing when possible, fall back to generic.
Key insight: columnar works when fields ALIGN. We need smarter field detection.
"""
import re
import sys
import struct
from collections import defaultdict

def detect_format(lines):
    """Detect log format from samples"""
    sample = lines[:100]
    
    # Try Apache CLF
    clf_pattern = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[^"]*"\s+\d+\s+\S+')
    clf_matches = sum(1 for l in sample if clf_pattern.match(l))
    if clf_matches > 80:
        return 'clf'
    
    # Try JSON
    json_matches = sum(1 for l in sample if l.strip().startswith('{'))
    if json_matches > 80:
        return 'json'
    
    # Try syslog (Month Day HH:MM:SS hostname)
    syslog_pattern = re.compile(r'^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+')
    syslog_matches = sum(1 for l in sample if syslog_pattern.match(l))
    if syslog_matches > 80:
        return 'syslog'
    
    # Try HDFS-style (YYMMDD HHMMSS PID LEVEL)
    hdfs_pattern = re.compile(r'^\d{6}\s+\d{6}\s+\d+\s+(INFO|WARN|ERROR|DEBUG)')
    hdfs_matches = sum(1 for l in sample if hdfs_pattern.match(l))
    if hdfs_matches > 80:
        return 'hdfs'
    
    return 'generic'

def parse_clf(line):
    """Parse Apache CLF log"""
    m = re.match(r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\S+)', line)
    if m:
        ip, ident, user, ts, request, status, size = m.groups()
        parts = request.split(' ', 2)
        method = parts[0] if parts else ''
        path = parts[1] if len(parts) > 1 else ''
        return {'ip': ip, 'ts': ts, 'method': method, 'path': path, 'status': status, 'size': size}
    return None

def parse_hdfs(line):
    """Parse HDFS log"""
    m = re.match(r'^(\d{6})\s+(\d{6})\s+(\d+)\s+(\w+)\s+(\S+):\s*(.*)$', line)
    if m:
        date, time, pid, level, component, msg = m.groups()
        # Extract block IDs and IPs from message
        blocks = re.findall(r'blk_-?\d+', msg)
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+(?::\d+)?', msg)
        # Create template from message
        tmpl = re.sub(r'blk_-?\d+', '<BLK>', msg)
        tmpl = re.sub(r'\d+\.\d+\.\d+\.\d+(?::\d+)?', '<IP>', tmpl)
        tmpl = re.sub(r'\b\d{6,}\b', '<NUM>', tmpl)
        return {'date': date, 'time': time, 'pid': pid, 'level': level, 
                'component': component, 'template': tmpl, 'blocks': blocks, 'ips': ips}
    return None

def parse_syslog(line):
    """Parse syslog format"""
    m = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$', line)
    if m:
        ts, host, prog, pid, msg = m.groups()
        return {'ts': ts, 'host': host, 'program': prog, 'pid': pid or '', 'message': msg}
    return None

def encode_structured(lines, fmt):
    """Encode structured logs into columnar format"""
    if fmt == 'clf':
        parser = parse_clf
    elif fmt == 'hdfs':
        parser = parse_hdfs
    elif fmt == 'syslog':
        parser = parse_syslog
    else:
        return None
    
    # Parse all lines
    parsed = []
    unparsed = []
    for i, line in enumerate(lines):
        p = parser(line)
        if p:
            parsed.append(p)
        else:
            unparsed.append((i, line))
    
    if len(parsed) < len(lines) * 0.8:
        return None  # Too many parse failures
    
    # Get all fields
    all_fields = set()
    for p in parsed:
        all_fields.update(p.keys())
    
    # Build column data
    columns = {f: [] for f in all_fields}
    for p in parsed:
        for f in all_fields:
            val = p.get(f, '')
            if isinstance(val, list):
                val = '|'.join(val)
            columns[f].append(str(val))
    
    return columns, unparsed

def dict_encode_column(values):
    """Dictionary encode a column"""
    unique = list(dict.fromkeys(values))
    val_to_id = {v: i for i, v in enumerate(unique)}
    
    # Dictionary
    dict_data = bytearray()
    dict_data.extend(struct.pack('<I', len(unique)))
    for v in unique:
        b = v.encode('utf-8', errors='replace')[:65535]
        dict_data.extend(struct.pack('<H', len(b)))
        dict_data.extend(b)
    
    # IDs
    if len(unique) <= 256:
        id_data = bytes(val_to_id[v] for v in values)
    elif len(unique) <= 65536:
        id_data = b''.join(struct.pack('<H', val_to_id[v]) for v in values)
    else:
        id_data = b''.join(struct.pack('<I', val_to_id[v]) for v in values)
    
    return bytes(dict_data), id_data, len(unique)

def main():
    input_file = sys.argv[1]
    
    with open(input_file, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]
    
    fmt = detect_format(lines)
    print(f"Detected format: {fmt}")
    print(f"Lines: {len(lines)}")
    
    if fmt in ('clf', 'hdfs', 'syslog'):
        result = encode_structured(lines, fmt)
        if result:
            columns, unparsed = result
            print(f"Parsed: {len(lines) - len(unparsed)}, Unparsed: {len(unparsed)}")
            
            # Encode columns
            total_size = 0
            with open(f"{input_file}.smart", 'wb') as f:
                f.write(struct.pack('<I', len(columns)))
                
                for name, values in columns.items():
                    dict_data, id_data, unique = dict_encode_column(values)
                    
                    name_b = name.encode('utf-8')
                    f.write(struct.pack('B', len(name_b)))
                    f.write(name_b)
                    f.write(struct.pack('<I', len(dict_data)))
                    f.write(dict_data)
                    f.write(struct.pack('<I', len(id_data)))
                    f.write(id_data)
                    
                    total_size += len(dict_data) + len(id_data)
                    print(f"  {name}: {unique} unique values")
            
            print(f"Encoded size: {total_size:,}")
            return
    
    print("Falling back to raw (no benefit expected)")
    # Just copy for comparison
    with open(f"{input_file}.smart", 'wb') as f:
        f.write('\n'.join(lines).encode('utf-8'))

if __name__ == '__main__':
    main()
