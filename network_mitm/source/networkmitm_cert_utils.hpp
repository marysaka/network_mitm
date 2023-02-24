/*
 * Copyright (c) Mary <mary@mary.zone>
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
#include <vapours.hpp>


namespace ams::ssl::sf::impl {
    struct Certificate {
        Span<uint8_t> private_key;
        Span<uint8_t> public_key;

        Certificate() : private_key(), public_key() {}
        Certificate(Span<uint8_t> private_key, Span<uint8_t> public_key)
            : private_key(private_key), public_key(public_key) {}

        void Release() {
            delete[] private_key.data();
            delete[] public_key.data();
        }
    };

    bool ConvertPemToDer(Span<const uint8_t> pem_cert, Span<uint8_t> &der_cert, size_t &der_cert_size);
}

