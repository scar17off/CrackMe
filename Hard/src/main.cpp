#include <iostream>
#include <string>
#include <random>
#include <chrono>
#include <thread>
#include <functional>
#include <vector>
#include <windows.h>
#include <bitset>
#include <array>
#include <sstream>
#include <iomanip>
#include <memory>

using MathFunc = std::function<uint64_t(uint64_t, uint64_t)>;
using VerifyFunc = std::function<bool(int, const std::string&, const std::string&, uint64_t, uint64_t)>;
using StringFunc = std::function<std::string(const std::vector<uint64_t>&)>;

static std::array<uint64_t, 1024> g_storage;
static std::vector<uint64_t> g_string_parts;
static size_t g_key_pos = 0;
static uint64_t g_magic = 0xDEADBEEFCAFEBABE;

static uint64_t transform_value(uint64_t value, int depth, uint64_t seed) {
    uint64_t result = value;
    for(int i = 0; i < depth % 8; i++) {
        result = ((result << (seed % 7)) | (result >> (64 - (seed % 7)))) ^ (seed + i);
    }
    return result;
}

class StringTransformer {
private:
    using MathFunc = std::function<uint64_t(uint64_t, uint64_t)>;
    using StringFunc = std::function<std::string(const std::vector<uint64_t>&)>;
    
    std::vector<MathFunc> math_ops;
    std::vector<StringFunc> string_ops;
    uint64_t magic_seed;

    static uint64_t op_add(uint64_t a, uint64_t b) { return a + b; }
    static uint64_t op_sub(uint64_t a, uint64_t b) { return a - b; }
    static uint64_t op_mul(uint64_t a, uint64_t b) { return a * b; }
    static uint64_t op_xor(uint64_t a, uint64_t b) { return a ^ b; }
    static uint64_t op_and(uint64_t a, uint64_t b) { return a & b; }
    static uint64_t op_or(uint64_t a, uint64_t b)  { return a | b; }
    static uint64_t op_rol(uint64_t a, uint64_t b) { return (a << (b % 64)) | (a >> (64 - (b % 64))); }
    static uint64_t op_ror(uint64_t a, uint64_t b) { return (a >> (b % 64)) | (a << (64 - (b % 64))); }

    static std::string str_combine_hex(const std::vector<uint64_t>& parts) {
        std::stringstream ss;
        for(auto part : parts) {
            ss << static_cast<char>(part & 0xFF);
        }
        return ss.str();
    }

    static std::string str_combine_dec(const std::vector<uint64_t>& parts) {
        std::string result;
        for(auto part : parts) {
            result += static_cast<char>((part % 26) + 'a');
        }
        return result;
    }

    static std::string str_combine_xor(const std::vector<uint64_t>& parts) {
        std::string result;
        uint64_t xor_key = parts[0];
        for(size_t i = 1; i < parts.size(); i++) {
            result += static_cast<char>(parts[i] ^ xor_key);
        }
        return result;
    }

public:
    StringTransformer(uint64_t seed) : magic_seed(seed) {
        math_ops = {op_add, op_sub, op_mul, op_xor, op_and, op_or, op_rol, op_ror};
        string_ops = {str_combine_hex, str_combine_dec, str_combine_xor};
    }

    std::vector<uint64_t> string_to_parts(const std::string& input, uint64_t seed) {
        std::vector<uint64_t> parts;
        for(char c : input) {
            uint64_t transformed = static_cast<uint64_t>(c);
            for(size_t i = 0; i < math_ops.size(); i++) {
                transformed = math_ops[i](transformed, seed + i);
            }
            parts.push_back(transformed);
        }
        return parts;
    }

    std::string parts_to_string(const std::vector<uint64_t>& parts, uint64_t seed) {
        return string_ops[seed % string_ops.size()](parts);
    }
};

class KeyVerifier {
private:
    using VerifyFunc = std::function<bool(int, const std::string&, const std::string&, uint64_t, uint64_t)>;
    std::vector<VerifyFunc> verify_funcs;
    std::shared_ptr<StringTransformer> transformer;
    uint64_t magic;

    bool verify_level_1(int depth, const std::string& input, const std::string& key, uint64_t magic, uint64_t seed) {
        if (depth <= 0) return compare_transformed_strings(input, key, seed);
        
        uint64_t new_magic = transform_value(magic, depth, seed);
        uint64_t new_seed = new_magic ^ seed;
        return verify_funcs[new_magic % verify_funcs.size()](depth - 1, input, key, new_magic, new_seed);
    }

    bool verify_level_2(int depth, const std::string& input, const std::string& key, uint64_t magic, uint64_t seed) {
        if (depth <= 0) return input.length() == key.length() && compare_transformed_strings(input, key, seed);
        
        uint64_t new_magic = transform_value(magic + depth, depth * 2, seed);
        uint64_t new_seed = transform_value(seed, depth, magic);
        
        return verify_funcs[new_seed % verify_funcs.size()](depth - 1, input, key, new_magic, new_seed);
    }

    bool verify_level_3(int depth, const std::string& input, const std::string& key, uint64_t magic, uint64_t seed) {
        if (depth <= 0) return !input.empty() && compare_transformed_strings(input, key, seed);
        
        uint64_t new_magic = transform_value(magic ^ seed, depth + 3, magic);
        uint64_t new_seed = transform_value(seed + magic, depth, seed);
        
        return verify_funcs[new_magic % verify_funcs.size()](depth - 1, input, key, new_magic, new_seed);
    }

    bool compare_transformed_strings(const std::string& input, const std::string& key, uint64_t seed) {
        auto input_parts = transformer->string_to_parts(input, seed);
        auto key_parts = transformer->string_to_parts(key, seed);
        
        if(input_parts.size() != key_parts.size()) return false;
        
        auto transformed_input = transformer->parts_to_string(input_parts, seed);
        auto transformed_key = transformer->parts_to_string(key_parts, seed);
        
        return transformed_input == transformed_key;
    }

public:
    KeyVerifier(uint64_t magic_value) : magic(magic_value) {
        transformer = std::make_shared<StringTransformer>(magic);
        
        verify_funcs = {
            [this](int d, const std::string& i, const std::string& k, uint64_t m, uint64_t s) { 
                return this->verify_level_1(d, i, k, m, s); 
            },
            [this](int d, const std::string& i, const std::string& k, uint64_t m, uint64_t s) { 
                return this->verify_level_2(d, i, k, m, s); 
            },
            [this](int d, const std::string& i, const std::string& k, uint64_t m, uint64_t s) { 
                return this->verify_level_3(d, i, k, m, s); 
            }
        };
    }

    bool verify(const std::string& input, const std::string& key) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;
        
        int depth = 15 + (gen() % 10);
        uint64_t current_magic = magic ^ dis(gen);
        uint64_t seed = dis(gen);
        
        return verify_funcs[current_magic % verify_funcs.size()](depth, input, key, current_magic, seed);
    }

    std::shared_ptr<StringTransformer> get_transformer() { return transformer; }
};

static const uint8_t obf_data[] = {
    // "Access granted!\n"
    0x41 ^ 0xFF, 0x63 ^ 0xFF, 0x63 ^ 0xFF, 0x65 ^ 0xFF, 
    0x73 ^ 0xFF, 0x73 ^ 0xFF, 0x20 ^ 0xFF, 0x67 ^ 0xFF,
    0x72 ^ 0xFF, 0x61 ^ 0xFF, 0x6E ^ 0xFF, 0x74 ^ 0xFF,
    0x65 ^ 0xFF, 0x64 ^ 0xFF, 0x21 ^ 0xFF, 0x0A ^ 0xFF,

    // "Access denied!\n"
    0x41 ^ 0xAA, 0x63 ^ 0xAA, 0x63 ^ 0xAA, 0x65 ^ 0xAA,
    0x73 ^ 0xAA, 0x73 ^ 0xAA, 0x20 ^ 0xAA, 0x64 ^ 0xAA,
    0x65 ^ 0xAA, 0x6E ^ 0xAA, 0x69 ^ 0xAA, 0x65 ^ 0xAA,
    0x64 ^ 0xAA, 0x21 ^ 0xAA, 0x0A ^ 0xAA,

    // "Enter key: "
    0x45 ^ 0x55, 0x6E ^ 0x55, 0x74 ^ 0x55, 0x65 ^ 0x55,
    0x72 ^ 0x55, 0x20 ^ 0x55, 0x6B ^ 0x55, 0x65 ^ 0x55,
    0x79 ^ 0x55, 0x3A ^ 0x55, 0x20 ^ 0x55,

    // "Initializing...\n"
    0x49 ^ 0x33, 0x6E ^ 0x33, 0x69 ^ 0x33, 0x74 ^ 0x33,
    0x69 ^ 0x33, 0x61 ^ 0x33, 0x6C ^ 0x33, 0x69 ^ 0x33,
    0x7A ^ 0x33, 0x69 ^ 0x33, 0x6E ^ 0x33, 0x67 ^ 0x33,
    0x2E ^ 0x33, 0x2E ^ 0x33, 0x2E ^ 0x33, 0x0A ^ 0x33,

    // "Debug: Generated key is: "
    0x44 ^ 0x77, 0x65 ^ 0x77, 0x62 ^ 0x77, 0x75 ^ 0x77,
    0x67 ^ 0x77, 0x3A ^ 0x77, 0x20 ^ 0x77, 0x47 ^ 0x77,
    0x65 ^ 0x77, 0x6E ^ 0x77, 0x65 ^ 0x77, 0x72 ^ 0x77,
    0x61 ^ 0x77, 0x74 ^ 0x77, 0x65 ^ 0x77, 0x64 ^ 0x77,
    0x20 ^ 0x77, 0x6B ^ 0x77, 0x65 ^ 0x77, 0x79 ^ 0x77,
    0x20 ^ 0x77, 0x69 ^ 0x77, 0x73 ^ 0x77, 0x3A ^ 0x77,
    0x20 ^ 0x77,

    // "Error: "
    0x45 ^ 0x88, 0x72 ^ 0x88, 0x72 ^ 0x88, 0x6F ^ 0x88,
    0x72 ^ 0x88, 0x3A ^ 0x88, 0x20 ^ 0x88,

    // "\nPress Enter to exit..."
    0x0A ^ 0x44, 0x50 ^ 0x44, 0x72 ^ 0x44, 0x65 ^ 0x44,
    0x73 ^ 0x44, 0x73 ^ 0x44, 0x20 ^ 0x44, 0x45 ^ 0x44,
    0x6E ^ 0x44, 0x74 ^ 0x44, 0x65 ^ 0x44, 0x72 ^ 0x44,
    0x20 ^ 0x44, 0x74 ^ 0x44, 0x6F ^ 0x44, 0x20 ^ 0x44,
    0x65 ^ 0x44, 0x78 ^ 0x44, 0x69 ^ 0x44, 0x74 ^ 0x44,
    0x2E ^ 0x44, 0x2E ^ 0x44, 0x2E ^ 0x44
};

static const size_t STR_OFFSETS[] = {0, 16, 31, 42, 58, 83, 90};
static const size_t STR_LENGTHS[] = {16, 15, 11, 16, 25, 7, 23};

class StringDecoder {
private:
    static uint64_t state;
    
    static void mutate_state() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state *= 0xDEADBEEFCAFEBABE;
    }
    
    static std::string decode_string(size_t offset, size_t length) {
        std::string result;
        uint8_t key = static_cast<uint8_t>(state & 0xFF);
        
        for(size_t i = 0; i < length; i++) {
            uint8_t decoded;
            switch(offset) {
                case 0:  decoded = obf_data[offset + i] ^ 0xFF; break; // Access granted
                case 16: decoded = obf_data[offset + i] ^ 0xAA; break; // Access denied
                case 31: decoded = obf_data[offset + i] ^ 0x55; break; // Enter key
                case 42: decoded = obf_data[offset + i] ^ 0x33; break; // Initializing
                case 58: decoded = obf_data[offset + i] ^ 0x77; break; // Debug
                case 83: decoded = obf_data[offset + i] ^ 0x88; break; // Error
                default: decoded = obf_data[offset + i];
            }
            result += static_cast<char>(decoded);
        }
        
        return result;
    }

public:
    static std::string get_string(uint64_t id) {
        state = id * 0xA5A5A5A5A5A5A5A5;
        mutate_state();
        
        switch(id) {
            case 0xDEADBEEF: return decode_string(STR_OFFSETS[0], STR_LENGTHS[0]);
            case 0xCAFEBABE: return decode_string(STR_OFFSETS[1], STR_LENGTHS[1]);
            case 0xFEEDFACE: return decode_string(STR_OFFSETS[2], STR_LENGTHS[2]);
            case 0xBADC0DE0: return decode_string(STR_OFFSETS[3], STR_LENGTHS[3]);
            case 0xDEADC0DE: return decode_string(STR_OFFSETS[4], STR_LENGTHS[4]);
            case 0xBAADF00D: return decode_string(STR_OFFSETS[5], STR_LENGTHS[5]);
            case 0xDEADDEAD: return decode_string(STR_OFFSETS[6], STR_LENGTHS[6]);
            default: return "";
        }
    }
};

uint64_t StringDecoder::state = 0;

#define ENCODE_LINE(x) (static_cast<uint64_t>(__LINE__) * x)
#define STR_ACCESS_GRANTED  StringDecoder::get_string(0xDEADBEEF)
#define STR_ACCESS_DENIED   StringDecoder::get_string(0xCAFEBABE)
#define STR_ENTER_KEY      StringDecoder::get_string(0xFEEDFACE)
#define STR_INITIALIZING   StringDecoder::get_string(0xBADC0DE0)
#define STR_DEBUG_KEY      StringDecoder::get_string(0xDEADC0DE)
#define STR_ERROR          StringDecoder::get_string(0xBAADF00D)
#define STR_PAUSE          StringDecoder::get_string(0xDEADDEAD)

std::string generate_key() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(97, 122);
    std::uniform_int_distribution<> pos(0, 128);
    
    std::string key;
    for(int i = 0; i < 8; i++) {
        key += static_cast<char>(dis(gen));
    }
    
    g_key_pos = pos(gen);
    g_string_parts = StringTransformer(g_magic).string_to_parts(key, g_magic);
    
    return key;
}

int main() {
    auto verifier = std::make_unique<KeyVerifier>(0xDEADBEEFCAFEBABE);
    auto transformer = verifier->get_transformer();
    
    std::cout << STR_INITIALIZING;
    
    try {
        std::string key = generate_key();
        std::cout << STR_DEBUG_KEY << key << std::endl;
        
        std::string input;
        std::cout << STR_ENTER_KEY;
        std::getline(std::cin, input);
        
        if(verifier->verify(input, key)) {
            std::cout << STR_ACCESS_GRANTED;
        } else {
            std::cout << STR_ACCESS_DENIED;
        }

        std::cout << STR_PAUSE;
        std::cin.get();
        
        return verifier->verify(input, key) ? 0 : 1;
    }
    catch (const std::exception& e) {
        std::cerr << STR_ERROR << e.what() << std::endl;
        
        std::cout << STR_PAUSE;
        std::cin.get();
        
        return 1;
    }
}