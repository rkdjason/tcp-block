#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t version_ihl_;
    uint8_t tos_;
    uint16_t total_length_;
    uint16_t id_;
    uint16_t flags_fragment_;
    uint8_t ttl_;
    uint8_t protocol_;
    uint16_t checksum_;
    Ip src_ip_;
    Ip dst_ip_;

    uint8_t version() const { return (version_ihl_ >> 4) & 0x0F; }
    uint8_t ihl() const { return version_ihl_ & 0x0F; }
    uint16_t total_length() const { return ntohs(total_length_); }
    uint8_t protocol() const { return protocol_; }

    enum: uint8_t {
        TCP = 6
    };

    enum: uint16_t {
        DF = 0x4000
    };
};
#pragma pack(pop)
