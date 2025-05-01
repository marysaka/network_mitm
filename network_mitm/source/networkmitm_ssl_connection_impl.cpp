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
#include "networkmitm_ssl_connection_impl.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result
SslConnectionImpl::SetSocketDescriptor(u32 input_socket_fd,
                                       ams::sf::Out<u32> output_socket_fd) {
    Result res = sslConnectionSetSocketDescriptor_sfMitm(
        m_forward_service.get(), input_socket_fd,
        output_socket_fd.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::SetHostName(const ams::sf::InBuffer &hostname) {
    Result res = sslConnectionSetHostName_sfMitm(
        m_forward_service.get(), hostname.GetPointer(), hostname.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslConnectionImpl::SetVerifyOption(const ams::ssl::sf::VerifyOption &option) {
    Result res = sslConnectionSetVerifyOption_sfMitm(m_forward_service.get(),
                                                     static_cast<u32>(option));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::SetIoMode(const ams::ssl::sf::IoMode &mode) {
    Result res = sslConnectionSetIoMode_sfMitm(m_forward_service.get(),
                                               static_cast<u32>(mode));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetSocketDescriptor(ams::sf::Out<u32> socket_fd) {
    Result res = sslConnectionGetSocketDescriptor_sfMitm(
        m_forward_service.get(), socket_fd.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetHostName(ams::sf::Out<u32> hostname_length,
                                      const ams::sf::OutBuffer &hostname) {
    Result res = sslConnectionGetHostName_sfMitm(
        m_forward_service.get(), hostname_length.GetPointer(),
        hostname.GetPointer(), hostname.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetVerifyOption(
    ams::sf::Out<ams::ssl::sf::VerifyOption> option) {
    Result res = sslConnectionGetVerifyOption_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(option.GetPointer()));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetIoMode(ams::sf::Out<ams::ssl::sf::IoMode> mode) {
    Result res = sslConnectionGetIoMode_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(mode.GetPointer()));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::DoHandshake() {
    Result res = sslConnectionDoHandshake_sfMitm(m_forward_service.get());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::DoHandshakeGetServerCert(
    ams::sf::Out<u32> buffer_size, ams::sf::Out<u32> certificates_count,
    const ams::sf::OutBuffer &server_cert_buffer) {
    Result res = sslConnectionDoHandshakeGetServerCert_sfMitm(
        m_forward_service.get(), buffer_size.GetPointer(),
        certificates_count.GetPointer(), server_cert_buffer.GetPointer(),
        server_cert_buffer.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::Read(ams::sf::Out<u32> read_count,
                               const ams::sf::OutBuffer &buffer) {
    Result res = sslConnectionRead_sfMitm(
        m_forward_service.get(), read_count.GetPointer(), buffer.GetPointer(),
        buffer.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    if (m_writter != nullptr) {
        m_writter->Write(PcapDirection::Input, buffer.GetPointer(),
                         read_count.GetValue());
    }

    R_SUCCEED();
}

Result SslConnectionImpl::Write(const ams::sf::InBuffer &buffer,
                                ams::sf::Out<u32> write_count) {
    Result res =
        sslConnectionWrite_sfMitm(m_forward_service.get(), buffer.GetPointer(),
                                  buffer.GetSize(), write_count.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    if (m_writter != nullptr) {
        m_writter->Write(PcapDirection::Output, buffer.GetPointer(),
                         write_count.GetValue());
    }

    R_SUCCEED();
}

Result SslConnectionImpl::Pending(ams::sf::Out<u32> pending_count) {
    Result res = sslConnectionPending_sfMitm(m_forward_service.get(),
                                             pending_count.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::Peek(ams::sf::Out<u32> peek_count,
                               const ams::sf::OutBuffer &buffer) {
    Result res = sslConnectionPeek_sfMitm(
        m_forward_service.get(), peek_count.GetPointer(), buffer.GetPointer(),
        buffer.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslConnectionImpl::Poll(const ams::ssl::sf::PollEvent &poll_event, u32 timeout,
                        ams::sf::Out<ams::ssl::sf::PollEvent> out_poll_event) {
    Result res = sslConnectionPoll_sfMitm(
        m_forward_service.get(), static_cast<u32>(poll_event), timeout,
        reinterpret_cast<u32 *>(out_poll_event.GetPointer()));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetVerifyCertError() {
    Result res =
        sslConnectionGetVerifyCertError_sfMitm(m_forward_service.get());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetNeededServerCertBufferSize(
    ams::sf::Out<u32> needed_buffer_size) {
    Result res = sslConnectionGetNeededServerCertBufferSize_sfMitm(
        m_forward_service.get(), needed_buffer_size.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::SetSessionCacheMode(
    const ams::ssl::sf::SessionCacheMode &mode) {
    Result res = sslConnectionSetSessionCacheMode_sfMitm(
        m_forward_service.get(), static_cast<u32>(mode));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetSessionCacheMode(
    ams::sf::Out<ams::ssl::sf::SessionCacheMode> mode) {
    Result res = sslConnectionGetSessionCacheMode_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(mode.GetPointer()));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::FlushSessionCache() {
    Result res = sslConnectionFlushSessionCache_sfMitm(m_forward_service.get());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::SetRenegotiationMode(
    const ams::ssl::sf::RenegotiationMode &mode) {
    Result res = sslConnectionSetRenegotiationMode_sfMitm(
        m_forward_service.get(), static_cast<u32>(mode));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetRenegotiationMode(
    ams::sf::Out<ams::ssl::sf::RenegotiationMode> mode) {
    Result res = sslConnectionGetRenegotiationMode_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(mode.GetPointer()));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::SetOption(bool value,
                                    const ams::ssl::sf::OptionType &option) {
    Result res = sslConnectionSetOption_sfMitm(m_forward_service.get(), value,
                                               static_cast<u32>(option));

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetOption(const ams::ssl::sf::OptionType &value,
                                    ams::sf::Out<bool> option) {
    Result res = sslConnectionGetOption_sfMitm(
        m_forward_service.get(), static_cast<u32>(value), option.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetVerifyCertErrors(ams::sf::Out<u32> unk0,
                                              ams::sf::Out<u32> unk1,
                                              const ams::sf::OutBuffer &unk2) {
    Result res = sslConnectionGetVerifyCertErrors_sfMitm(
        m_forward_service.get(), unk0.GetPointer(), unk1.GetPointer(),
        unk2.GetPointer(), unk2.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetCipherInfo(u32 unk0,
                                        const ams::sf::OutBuffer &cipher_info) {
    Result res = sslConnectionGetCipherInfo_sfMitm(
        m_forward_service.get(), unk0, cipher_info.GetPointer(),
        cipher_info.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslConnectionImpl::SetNextAlpnProto(const ams::sf::InBuffer &alpn_proto) {
    Result res = sslConnectionSetNextAlpnProto_sfMitm(
        m_forward_service.get(), alpn_proto.GetPointer(), alpn_proto.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetNextAlpnProto(
    ams::sf::Out<ams::ssl::sf::AlpnProtoState> state,
    ams::sf::Out<u32> alpn_proto_out_size,
    const ams::sf::OutBuffer &alpn_proto) {
    Result res = sslConnectionGetNextAlpnProto_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(state.GetPointer()),
        alpn_proto_out_size.GetPointer(), alpn_proto.GetPointer(),
        alpn_proto.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslConnectionImpl::SetDtlsSocketDescriptor(u32 sock_fd,
                                           const ams::sf::InBuffer &sock_addr,
                                           ams::sf::Out<u32> out_sock_fd) {
    Result res = sslConnectionSetDtlsSocketDescriptor_sfMitm(
        m_forward_service.get(), sock_fd, sock_addr.GetPointer(),
        sock_addr.GetSize(), out_sock_fd.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslConnectionImpl::GetDtlsHandshakeTimeout(const ams::sf::OutBuffer &timespan) {
    Result res = sslConnectionGetDtlsHandshakeTimeout_sfMitm(
        m_forward_service.get(), timespan.GetPointer(), timespan.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslConnectionImpl::SetPrivateOption(const ams::ssl::sf::OptionType &option,
                                    u32 value) {
    Result res = sslConnectionSetPrivateOption_sfMitm(
        m_forward_service.get(), static_cast<u32>(option), value);

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::SetSrtpCiphers(const ams::sf::InBuffer &ciphers) {
    Result res = sslConnectionSetSrtpCiphers_sfMitm(
        m_forward_service.get(), ciphers.GetPointer(), ciphers.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetSrtpCipher(ams::sf::Out<u16> cipher) {
    Result res = sslConnectionGetSrtpCipher_sfMitm(m_forward_service.get(),
                                                   cipher.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result
SslConnectionImpl::ExportKeyingMaterial(const ams::sf::InBuffer &label,
                                        const ams::sf::InBuffer &context,
                                        const ams::sf::OutBuffer &material) {
    Result res = sslConnectionExportKeyingMaterial_sfMitm(
        m_forward_service.get(), label.GetPointer(), label.GetSize(),
        context.GetPointer(), context.GetSize(), material.GetPointer(),
        material.GetSize());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::SetIoTimeout(u32 timeout) {
    Result res =
        sslConnectionSetIoTimeout_sfMitm(m_forward_service.get(), timeout);

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetIoTimeout(ams::sf::Out<u32> timeout) {
    Result res = sslConnectionGetIoTimeout_sfMitm(m_forward_service.get(),
                                                  timeout.GetPointer());

    if (res.IsFailure()) {
        return res;
    }

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
