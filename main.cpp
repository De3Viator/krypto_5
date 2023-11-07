#include <iostream>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <openssl/sha.h>
#include <ctime>

class SHA1Context {
public:
    SHA1Context() {
        Reset();
    }

    void Reset() {
        Length_Low = 0;
        Length_High = 0;
        Message_Block_Index = 0;
        Computed = 0;
        Corrupted = 0;
        std::memset(Message_Block, 0, 64);
        std::memset(Intermediate_Hash, 0, 20);
        Intermediate_Hash[0] = 0x67452301;
        Intermediate_Hash[1] = 0xEFCDAB89;
        Intermediate_Hash[2] = 0x98BADCFE;
        Intermediate_Hash[3] = 0x10325476;
        Intermediate_Hash[4] = 0xC3D2E1F0;
    }

    int Input(const uint8_t *message_array, unsigned length) {
        if (!length) {
            return shaSuccess;
        }

        if (Computed) {
            Corrupted = shaStateError;
            return shaStateError;
        }

        while (length-- && !Corrupted) {
            Message_Block[Message_Block_Index++] = (*message_array & 0xFF);

            Length_Low += 8;
            if (Length_Low == 0) {
                Length_High++;
                if (Length_High == 0) {
                    Corrupted = 1;
                }
            }

            if (Message_Block_Index == 64) {
                ProcessMessageBlock();
            }

            message_array++;
        }

        return shaSuccess;
    }

    int Result(uint8_t Message_Digest[20]) {
        int i;

        if (Corrupted) {
            return Corrupted;
        }

        if (!Computed) {
            PadMessage();
            for (i = 0; i < 64; ++i) {
                Message_Block[i] = 0;
            }
            Length_Low = 0;
            Length_High = 0;
            Computed = 1;
        }

        for (i = 0; i < 20; ++i) {
            Message_Digest[i] = Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03));
        }

        return shaSuccess;
    }

private:
    void ProcessMessageBlock() {
        const uint32_t K[] = {
                0x5A827999,
                0x6ED9EBA1,
                0x8F1BBCDC,
                0xCA62C1D6
        };
        int t;
        uint32_t temp;
        uint32_t W[80];
        uint32_t A, B, C, D, E;

        for (t = 0; t < 16; t++) {
            W[t] = (Message_Block[t * 4] << 24) |
                   (Message_Block[t * 4 + 1] << 16) |
                   (Message_Block[t * 4 + 2] << 8) |
                   (Message_Block[t * 4 + 3]);
        }

        for (t = 16; t < 80; t++) {
            W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
        }

        A = Intermediate_Hash[0];
        B = Intermediate_Hash[1];
        C = Intermediate_Hash[2];
        D = Intermediate_Hash[3];
        E = Intermediate_Hash[4];

        for (t = 0; t < 20; t++) {
            temp = SHA1CircularShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
            E = D;
            D = C;
            C = SHA1CircularShift(30, B);
            B = A;
            A = temp;
        }

        for (t = 20; t < 40; t++) {
            temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
            E = D;
            D = C;
            C = SHA1CircularShift(30, B);
            B = A;
            A = temp;
        }

        for (t = 40; t < 60; t++) {
            temp = SHA1CircularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
            E = D;
            D = C;
            C = SHA1CircularShift(30, B);
            B = A;
            A = temp;
        }

        for (t = 60; t < 80; t++) {
            temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
            E = D;
            D = C;
            C = SHA1CircularShift(30, B);
            B = A;
            A = temp;
        }

        Intermediate_Hash[0] += A;
        Intermediate_Hash[1] += B;
        Intermediate_Hash[2] += C;
        Intermediate_Hash[3] += D;
        Intermediate_Hash[4] += E;

        Message_Block_Index = 0;
    }

    void PadMessage() {
        if (Message_Block_Index > 55) {
            Message_Block[Message_Block_Index++] = 0x80;
            while (Message_Block_Index < 64) {
                Message_Block[Message_Block_Index++] = 0;
            }
            ProcessMessageBlock();
            while (Message_Block_Index < 56) {
                Message_Block[Message_Block_Index++] = 0;
            }
        } else {
            Message_Block[Message_Block_Index++] = 0x80;
            while (Message_Block_Index < 56) {
                Message_Block[Message_Block_Index++] = 0;
            }
        }

        Message_Block[56] = Length_High >> 24;
        Message_Block[57] = Length_High >> 16;
        Message_Block[58] = Length_High >> 8;
        Message_Block[59] = Length_High;
        Message_Block[60] = Length_Low >> 24;
        Message_Block[61] = Length_Low >> 16;
        Message_Block[62] = Length_Low >> 8;
        Message_Block[63] = Length_Low;
        ProcessMessageBlock();
    }

    uint32_t SHA1CircularShift(int bits, uint32_t word) {
        return ((word << bits) | (word >> (32 - bits)));
    }

    enum {
        shaSuccess = 0,
        shaStateError
    };

    uint32_t Intermediate_Hash[5];
    uint32_t Length_Low;
    uint32_t Length_High;
    int Message_Block_Index;
    uint8_t Message_Block[64];
    int Computed;
    int Corrupted;
};

std::string openssl_sha1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

void CalculateSHA1(const char* message, unsigned length) {
    SHA1Context sha;
    uint8_t Message_Digest[20];

    sha.Reset();
    sha.Input((const uint8_t*)message, length);
    sha.Result(Message_Digest);

    std::cout << "Message Digest for '" << message << "': ";
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < 20; ++i) {
        std::cout << std::setw(2) << static_cast<int>(Message_Digest[i]);
    }
    std::cout << std::dec << std::endl;
    std::string openssl_result = openssl_sha1(message);
    std::cout <<"OpenSSL's message digest for '" << message << "': "<<openssl_result<<std::endl;
}


int main() {
//    std::clock_t clock_start = std::clock();
    const char* messages[] = {
            "Hello, World!",
            "This is a longer message that will require multiple blocks.",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec posuere, nibh id lacinia."
    };

    for (const char* message : messages) {
        unsigned length = std::strlen(message);
        CalculateSHA1(message, length);
    }
//    std::clock_t clock_end = std::clock();
//    double duration = static_cast<double>(clock_end - clock_start) / CLOCKS_PER_SEC;
//    std::cout << "Time: " << duration << " s" << std::endl;

    return 0;
}
