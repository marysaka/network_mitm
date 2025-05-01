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

#include "networkmitm_utils.hpp"
#include <mbedtls/base64.h>

namespace ams::ssl::sf::impl {
extern Span<uint8_t> g_ca_certificate_public_key_der;

bool ConvertPemToDer(Span<const uint8_t> pem_cert, Span<uint8_t> &der_cert,
                     size_t &der_cert_size) {
    const char *s1;
    const char *s2;
    const char *end = (const char *)(pem_cert.data() + pem_cert.size_bytes());
    size_t len = 0;

    s1 = strstr((const char *)pem_cert.data(), "-----BEGIN");

    if (s1 == nullptr) {
        return false;
    }

    s2 = strstr((const char *)pem_cert.data(), "-----END");

    if (s2 == nullptr) {
        return false;
    }

    s1 += 10;

    while (s1 < end && *s1 != '-') {
        s1++;
    }

    while (s1 < end && *s1 == '-') {
        s1++;
    }

    if (*s1 == '\r') {
        s1++;
    }

    if (*s1 == '\n') {
        s1++;
    }

    if (s2 <= s1 || s2 > end) {
        return false;
    }

    if (mbedtls_base64_decode(nullptr, 0, &len, (const unsigned char *)s1,
                              s2 - s1) ==
        MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        return false;
    }

    if (len > der_cert.size_bytes()) {
        return false;
    }

    if (mbedtls_base64_decode(der_cert.data(), len, &len,
                              (const unsigned char *)s1, s2 - s1) != 0) {
        return false;
    }

    der_cert_size = len;

    return true;
}

Result
PatchCertificates(const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
                  ams::sf::Out<u32> certificates_count,
                  const ams::sf::OutBuffer &certificates) {
    if (g_ca_certificate_public_key_der.empty()) {
        R_SUCCEED();
    }

    bool should_inject = false;

    for (size_t i = 0; i < ids.GetSize(); i++) {
        if (ids[i] == ams::ssl::sf::CaCertificateId::NintendoClass2CAG3 ||
            ids[i] == ams::ssl::sf::CaCertificateId::All) {
            should_inject = true;
            break;
        }
    }

    if (should_inject) {
        const auto certificates_count_value = certificates_count.GetValue();

        BuiltInCertificateInfo *infos =
            reinterpret_cast<BuiltInCertificateInfo *>(
                certificates.GetPointer());

        u64 target_offset =
            infos[certificates_count_value - 1].certificate_data_offset +
            infos[certificates_count_value - 1].certificate_data_size;

        memcpy(certificates.GetPointer() + target_offset,
               g_ca_certificate_public_key_der.data(),
               g_ca_certificate_public_key_der.size_bytes());

        bool found_target_ca = false;

        for (size_t i = 0; i < certificates_count_value; i++) {
            if (infos[i].id ==
                ams::ssl::sf::CaCertificateId::NintendoClass2CAG3) {
                infos[i].certificate_data_offset = target_offset;
                infos[i].certificate_data_size =
                    g_ca_certificate_public_key_der.size_bytes();

                found_target_ca = true;
                break;
            }
        }

        if (!found_target_ca) {
            AMS_LOG("GetCertificates injection failed?! couldn't find the "
                    "target CA in output!\n");
        }
    }
    R_SUCCEED();
}

Result PatchCertificateBufSize(
    const ams::sf::InArray<ams::ssl::sf::CaCertificateId> &ids,
    ams::sf::Out<u32> buffer_size) {
    bool should_inject = false;

    for (size_t i = 0; i < ids.GetSize(); i++) {
        if (ids[i] == ams::ssl::sf::CaCertificateId::NintendoClass2CAG3 ||
            ids[i] == ams::ssl::sf::CaCertificateId::All) {
            should_inject = true;
            break;
        }
    }

    if (should_inject) {
        buffer_size.SetValue(buffer_size.GetValue() +
                             g_ca_certificate_public_key_der.size_bytes());
    }
    R_SUCCEED();
}
} // namespace ams::ssl::sf::impl