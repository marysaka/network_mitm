/*
 * Copyright (c) Mary Guillemard <mary@mary.zone>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once
#include <stratosphere.hpp>
#include "networkmitm_ssl_types.hpp"

namespace ams::ssl::sf::impl {
    bool ConvertPemToDer(Span<const uint8_t> pem_cert, Span<uint8_t> &der_cert, size_t &der_cert_size);

    enum class TrustedCertStatus : u32 {
        Removed,
        EnabledTrusted,
        EnabledNotTrusted,
        Revoked,
    };

    struct BuiltInCertificateInfo {
        ams::ssl::sf::CaCertificateId id;
        TrustedCertStatus status;
        uint64_t certificate_data_size;
        uint64_t certificate_data_offset;
    };

    Result PatchCertificates(const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> certificates_count, const ams::sf::OutBuffer &certificates);
    Result PatchCertificateBufSize(const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids, ams::sf::Out<u32> buffer_size);
}

