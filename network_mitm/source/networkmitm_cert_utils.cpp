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

#include "networkmitm_cert_utils.hpp"
#include <mbedtls/base64.h>

namespace ams::ssl::sf::impl {
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
} // namespace ams::ssl::sf::impl