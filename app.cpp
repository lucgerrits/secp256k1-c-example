/**
 * @file app.cpp
 * @date 01/2021
 * @author Luc Gerrits <luc.gerrits@univ-cotedazur.fr>
 * @brief Example of Cpp program using the secp256k1 library.
 * @version 0.1
 */

#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <chrono>

//secp256k1
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"

//my utils lib
#include "blockchain-utils/utils.hpp"
BLOCKCHAIN_UTILS myBCutils;

#define PRIVATE_KEY "0152fdf6e81e0a694cf8f361e14d32d8b25e605c669dc06940c500c546ee8a3f"
#define PUBLIC_KEY "0265e1a0353a5de3ad229f0c96fe4851949c856d5ad57717d4615c981ddea1f841"
#define PRIVATE_KEY_SIZE 32
#define PUBLIC_KEY_SIZE 64
#define PUBLIC_KEY_SERILIZED_SIZE 33
#define PUBLIC_KEY_UNCOMPRESSED_SIZE 65
#define SIGNATURE_SERILIZED_SIZE 64
#define HASH_SHA256_SIZE 32
#define VERBOSE false

//////////////////////////////////////////////////////////////////
//To show errors:
void abort(void) __THROW __attribute__((__noreturn__));
#define TEST_FAILURE(msg)                                        \
    do                                                           \
    {                                                            \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
        abort();                                                 \
    } while (0)
#define EXPECT(x, c) __builtin_expect((x), (c))
#define CHECK(cond)                                        \
    do                                                     \
    {                                                      \
        if (EXPECT(!(cond), 0))                            \
        {                                                  \
            TEST_FAILURE("test condition failed: " #cond); \
        }                                                  \
    } while (0)
//////////////////////////////////////////////////////////////////

struct KeyPair
{
    std::string privKey_str = PRIVATE_KEY;
    std::string pubKey_str = PUBLIC_KEY;
    std::string pubKey_ucompressed_str = "PUBLIC_KEY";
    SECP256K1_API::secp256k1_pubkey pubkey;
    unsigned char privKey_uchar[PRIVATE_KEY_SIZE];
    unsigned char pubKey_uchar[PUBLIC_KEY_SERILIZED_SIZE];
    unsigned char pubKey_ucompressed_uchar[PUBLIC_KEY_UNCOMPRESSED_SIZE];
    size_t pubKey_ucompressed_len = PUBLIC_KEY_UNCOMPRESSED_SIZE;
};

void showParseError(char *argv[])
{
    std::cout << "Example of C program using the secp256k1 library. \n"
              << "Usage: " << argv[0] << " <option(s)>\n"
              << "Options:\n"
              << "\t-h,--help\t\tShow this help message\n"
              << "\t--sign <message>  \t\tBuild signature of <message>\n"
              << std::endl;
}
int parseArgs(int argc, char *argv[], std::string &command, std::string &message)
{
    if (argc < 2)
    {
        showParseError(argv);
        return 1;
    }
    else
    {
        if (strcmp(argv[1], "--sign") == 0)
        {
            if (argc < 3)
            {
                showParseError(argv);
                return 1;
            }
            command = "sign";
            message = argv[2];
        }
        else
        {
            showParseError(argv);
            return 1;
        }
        return 0;
    }
}

void init(SECP256K1_API::secp256k1_context *&ctx, KeyPair &myKeyPair)
{
    std::cout << "***INIT***" << std::endl;
    ctx = SECP256K1_API::secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    std::cout << "***Loading keys***" << std::endl;
    myBCutils.HexStrToUchar(myKeyPair.pubKey_uchar, PUBLIC_KEY, PUBLIC_KEY_SERILIZED_SIZE);
    CHECK(SECP256K1_API::secp256k1_ec_pubkey_parse(ctx, &myKeyPair.pubkey, myKeyPair.pubKey_uchar, PUBLIC_KEY_SERILIZED_SIZE) == 1);

    CHECK(SECP256K1_API::secp256k1_ec_pubkey_serialize(ctx, myKeyPair.pubKey_ucompressed_uchar, &myKeyPair.pubKey_ucompressed_len, &myKeyPair.pubkey, SECP256K1_EC_UNCOMPRESSED) == 1);

    myKeyPair.pubKey_ucompressed_str = myBCutils.UcharToHexStr(myKeyPair.pubKey_ucompressed_uchar, myKeyPair.pubKey_ucompressed_len);

    myBCutils.HexStrToUchar(myKeyPair.privKey_uchar, PRIVATE_KEY, PRIVATE_KEY_SIZE);
    CHECK(SECP256K1_API::secp256k1_ec_seckey_verify(ctx, myKeyPair.privKey_uchar) == 1);

    std::cout << std::left;
    std::cout << std::setw(20) << "Private Key: " << myKeyPair.privKey_str << std::endl;
    std::cout << std::setw(20) << "Public Key: " << myKeyPair.pubKey_ucompressed_str << std::endl;
    std::cout << std::setw(20) << "Public Key (compressed): " << myKeyPair.pubKey_str << std::endl;
}

void sign(SECP256K1_API::secp256k1_context *&ctx, KeyPair &myKeyPair, std::string message)
{
    std::cout << "***SIGN***" << std::endl;
    std::cout << std::setw(20) << "Message: " << message << std::endl;

    SECP256K1_API::secp256k1_ecdsa_signature signature;
    unsigned char signature_serilized[SIGNATURE_SERILIZED_SIZE];
    unsigned char message_hash_uchar[HASH_SHA256_SIZE];
    std::string message_hash_str = myBCutils.sha256(message);
    myBCutils.HexStrToUchar(message_hash_uchar, message_hash_str.c_str(), HASH_SHA256_SIZE);
    std::cout << std::setw(20) << "Message (SHA256): " << message_hash_str << std::endl;

    CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_uchar, myKeyPair.privKey_uchar, NULL, NULL) == 1); //make signature
    CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);

    std::string signature_str = myBCutils.UcharToHexStr(signature.data, SIGNATURE_SERILIZED_SIZE);
    std::string signature_compressed_str = myBCutils.UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
    std::cout << std::setw(20) << "Signature: " << signature_str << std::endl;
    std::cout << std::setw(20) << "Signature (compressed): " << signature_compressed_str << std::endl;
}

void clear_program(SECP256K1_API::secp256k1_context *ctx)
{
    std::cout << "***CLEARING UP***" << std::endl;
    SECP256K1_API::secp256k1_context_destroy(ctx);
}
//////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
    std::cout << "(Start chrono)" << std::endl;
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point end;
    std::string command = "", message = "";
    if (int exit = parseArgs(argc, argv, command, message))
        return exit;

    static SECP256K1_API::secp256k1_context *ctx;
    KeyPair myKeyPair;
    init(ctx, myKeyPair);

    sign(ctx, myKeyPair, message);

    end = std::chrono::steady_clock::now();
    std::cout << "(Time difference = " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()
              << "[µs])" << std::endl;
    clear_program(ctx);
    return 0;
}
