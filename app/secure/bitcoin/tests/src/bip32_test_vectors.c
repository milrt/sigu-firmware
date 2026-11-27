// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip32_test_vectors.h"

// Test vectors from:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Test_Vectors

static const uint8_t vector1_seed[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t vector2_seed[] = {
    0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea, 0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
    0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba, 0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
    0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a, 0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
    0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a, 0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42};
static const uint8_t vector3_seed[] = {
    0x4b, 0x38, 0x15, 0x41, 0x58, 0x3b, 0xe4, 0x42, 0x33, 0x46, 0xc6, 0x43, 0x85, 0x0d, 0xa4, 0xb3,
    0x20, 0xe4, 0x6a, 0x87, 0xae, 0x3d, 0x2a, 0x4e, 0x6d, 0xa1, 0x1e, 0xba, 0x81, 0x9c, 0xd4, 0xac,
    0xba, 0x45, 0xd2, 0x39, 0x31, 0x9a, 0xc1, 0x4f, 0x86, 0x3b, 0x8d, 0x5a, 0xb5, 0xa0, 0xd0, 0xc6,
    0x4d, 0x2e, 0x8a, 0x1e, 0x7d, 0x14, 0x57, 0xdf, 0x2e, 0x5a, 0x3c, 0x51, 0xc7, 0x32, 0x35, 0xbe};
static const uint8_t vector4_seed[] = {
    0x3d, 0xdd, 0x56, 0x02, 0x28, 0x58, 0x99, 0xa9, 0x46, 0x11, 0x45, 0x06, 0x15, 0x7c, 0x79, 0x97,
    0xe5, 0x44, 0x45, 0x28, 0xf3, 0x00, 0x3f, 0x61, 0x34, 0x71, 0x21, 0x47, 0xdb, 0x19, 0xb6, 0x78};

const bip32_test_vector_t bip32_test_vectors[BIP32_TEST_VECTOR_COUNT] = {
    // Test Vector 1
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m",
     .xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqse"
             "fD265TMg7usUDFdp6W1E"
             "GMcet8"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0h",
     .xpub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1b"
             "gwQ9xv5ski8PX9rL2dZX"
             "vgGDnw"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0h/1",
     .xpub = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq5"
             "27Hqck2AxYysAA7xmALp"
             "puCkwQ"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0h/1/2h",
     .xpub = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n"
             "7epu4trkrX7x7DogT5Uv"
             "6fcLW5"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0h/1/2h/2",
     .xpub = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37s"
             "R62cfN7fe5JnJ7dh8zL4"
             "fiyLHV"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0H/1/2H/2/1000000000",
     .xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8y"
             "GasTvXEYBVPamhGW6cFJ"
             "odrTHy"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m",
     .xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6m"
             "r8BDzTJY47LJhkJ8UB7W"
             "EGuduB"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0",
     .xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDzne"
             "zpbZb7ap6r1D3tgFxHmw"
             "MkQTPH"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0/2147483647h",
     .xpub = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8R"
             "uJiHjaDMBU4Zn9h8LZNn"
             "BC5y4a"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0/2147483647h/1",
     .xpub = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89L"
             "ojfZ537wTfunKau47EL2"
             "dhHKon"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0/2147483647h/1/2147483646h",
     .xpub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2"
             "grBGRjaDMzQLcgJvLJuZ"
             "ZvRcEL"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0/2147483647h/1/2147483646h/2",
     .xpub = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2r"
             "nY5agb9rXpVGyy3bdW6E"
             "EgAtqt"},
    {.seed = vector3_seed,
     .seed_size = sizeof(vector3_seed),
     .path = "m",
     .xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1c"
             "ZAceL7SfJ1Z3GC8vBgp2"
             "epUt13"},
    {.seed = vector3_seed,
     .seed_size = sizeof(vector3_seed),
     .path = "m/0h",
     .xpub = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MY"
             "o6oDaPPLPxSb7gwQN3ih"
             "19Zm4Y"},

    {.seed = vector4_seed,
     .seed_size = sizeof(vector4_seed),
     .path = "m",
     .xpub = "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92"
             "mBXjByMRiJdba9wpnN37"
             "RLLAXa"},
    {.seed = vector4_seed,
     .seed_size = sizeof(vector4_seed),
     .path = "m/0h",
     .xpub = "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCj"
             "YdvpW2PU2jbUPFKsav5u"
             "t6Ch1m"},
    {.seed = vector4_seed,
     .seed_size = sizeof(vector4_seed),
     .path = "m/0h/1h",
     .xpub = "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C"
             "9T5XnxkopaeS7jGk1Gyy"
             "VziaMt"},

};
