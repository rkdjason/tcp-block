#pragma once

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct TcpHdr final {
    uint16_t src_port_;
    uint16_t dst_port_;
    uint32_t seq_num_;
    uint32_t ack_num_;
    uint8_t data_offset_reserved_;
    uint8_t flags_;
    uint16_t window_;
    uint16_t checksum_;
    uint16_t urgent_ptr_;

    uint16_t src_port() const { return ntohs(src_port_); }
    uint16_t dst_port() const { return ntohs(dst_port_); }
    uint32_t seq_num() const { return ntohl(seq_num_); }
    uint32_t ack_num() const { return ntohl(ack_num_); }
    uint8_t offset() const { return (data_offset_reserved_ >> 4) & 0x0F; }

    enum: uint8_t {
        FIN = 0x01,
        RST = 0x04,
        PSH = 0x08,
        ACK = 0x10
    };

    enum: uint16_t {
        Http = 80,
        Https = 443
    };
};
#pragma pack(pop)
