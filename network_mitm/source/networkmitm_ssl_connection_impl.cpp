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
#include "networkmitm_utils.hpp"
#include "shim/ssl_shim.h"
#include <stratosphere.hpp>

namespace ams::ssl::sf::impl {
Result
SslConnectionImpl::SetSocketDescriptor(u32 input_socket_fd,
                                       ams::sf::Out<u32> output_socket_fd) {
    R_TRY(sslConnectionSetSocketDescriptor_sfMitm(
        m_forward_service.get(), input_socket_fd,
        output_socket_fd.GetPointer()));

    R_SUCCEED();
}

Result SslConnectionImpl::SetHostName(const ams::sf::InBuffer &hostname) {
    R_TRY(sslConnectionSetHostName_sfMitm(
        m_forward_service.get(), hostname.GetPointer(), hostname.GetSize()));

    R_SUCCEED();
}

Result SslConnectionImpl::SetVerifyOptionReal(
    const ams::ssl::sf::VerifyOption &option) {
    R_TRY(sslConnectionSetVerifyOption_sfMitm(m_forward_service.get(),
                                              static_cast<u32>(option)));

    R_SUCCEED();
}

Result
SslConnectionImpl::SetVerifyOption(const ams::ssl::sf::VerifyOption &option) {
    if (g_should_disable_ssl_verification) {
        m_requested_option = option;
        R_SUCCEED();
    }

    return SetVerifyOptionReal(option);
}

Result SslConnectionImpl::SetIoMode(const ams::ssl::sf::IoMode &mode) {
    R_TRY(sslConnectionSetIoMode_sfMitm(m_forward_service.get(),
                                        static_cast<u32>(mode)));

    R_SUCCEED();
}

Result SslConnectionImpl::GetSocketDescriptor(ams::sf::Out<u32> socket_fd) {
    R_TRY(sslConnectionGetSocketDescriptor_sfMitm(m_forward_service.get(),
                                                  socket_fd.GetPointer()));

    R_SUCCEED();
}

Result SslConnectionImpl::GetHostName(ams::sf::Out<u32> hostname_length,
                                      const ams::sf::OutBuffer &hostname) {
    R_TRY(sslConnectionGetHostName_sfMitm(
        m_forward_service.get(), hostname_length.GetPointer(),
        hostname.GetPointer(), hostname.GetSize()));

    R_SUCCEED();
}

Result SslConnectionImpl::GetVerifyOption(
    ams::sf::Out<ams::ssl::sf::VerifyOption> option) {
    ams::ssl::sf::VerifyOption returned_value;
    R_TRY(sslConnectionGetVerifyOption_sfMitm(m_forward_service.get(),
                                              (u32 *)&returned_value));

    option.SetValue(g_should_disable_ssl_verification ? m_requested_option
                                                      : returned_value);

    R_SUCCEED();
}

Result SslConnectionImpl::GetIoMode(ams::sf::Out<ams::ssl::sf::IoMode> mode) {
    R_TRY(sslConnectionGetIoMode_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(mode.GetPointer())));

    R_SUCCEED();
}

Result SslConnectionImpl::DoHandshake() {
    R_TRY(sslConnectionDoHandshake_sfMitm(m_forward_service.get()));

    R_SUCCEED();
}

Result SslConnectionImpl::DoHandshakeGetServerCert(
    ams::sf::Out<u32> buffer_size, ams::sf::Out<u32> certificates_count,
    const ams::sf::OutBuffer &server_cert_buffer) {
    R_TRY(sslConnectionDoHandshakeGetServerCert_sfMitm(
        m_forward_service.get(), buffer_size.GetPointer(),
        certificates_count.GetPointer(), server_cert_buffer.GetPointer(),
        server_cert_buffer.GetSize()));

    R_SUCCEED();
}

Result SslConnectionImpl::Read(ams::sf::Out<u32> read_count,
                               const ams::sf::OutBuffer &buffer) {
    R_TRY(sslConnectionRead_sfMitm(m_forward_service.get(),
                                   read_count.GetPointer(), buffer.GetPointer(),
                                   buffer.GetSize()));

    if (m_writer != nullptr) {
        m_writer->Write(PcapDirection::Input, buffer.GetPointer(),
                        read_count.GetValue());
    }

    R_SUCCEED();
}

Result SslConnectionImpl::Write(const ams::sf::InBuffer &buffer,
                                ams::sf::Out<u32> write_count) {
    R_TRY(sslConnectionWrite_sfMitm(m_forward_service.get(),
                                    buffer.GetPointer(), buffer.GetSize(),
                                    write_count.GetPointer()));

    if (m_writer != nullptr) {
        m_writer->Write(PcapDirection::Output, buffer.GetPointer(),
                        write_count.GetValue());
    }

    R_SUCCEED();
}

Result SslConnectionImpl::Pending(ams::sf::Out<u32> pending_count) {
    R_TRY(sslConnectionPending_sfMitm(m_forward_service.get(),
                                      pending_count.GetPointer()));

    R_SUCCEED();
}

Result SslConnectionImpl::Peek(ams::sf::Out<u32> peek_count,
                               const ams::sf::OutBuffer &buffer) {
    R_TRY(sslConnectionPeek_sfMitm(m_forward_service.get(),
                                   peek_count.GetPointer(), buffer.GetPointer(),
                                   buffer.GetSize()));

    R_SUCCEED();
}

Result
SslConnectionImpl::Poll(const ams::ssl::sf::PollEvent &poll_event, u32 timeout,
                        ams::sf::Out<ams::ssl::sf::PollEvent> out_poll_event) {
    R_TRY(sslConnectionPoll_sfMitm(
        m_forward_service.get(), static_cast<u32>(poll_event), timeout,
        reinterpret_cast<u32 *>(out_poll_event.GetPointer())));

    R_SUCCEED();
}

Result SslConnectionImpl::GetVerifyCertError() {
    R_TRY(sslConnectionGetVerifyCertError_sfMitm(m_forward_service.get()));

    R_SUCCEED();
}

Result SslConnectionImpl::GetNeededServerCertBufferSize(
    ams::sf::Out<u32> needed_buffer_size) {
    R_TRY(sslConnectionGetNeededServerCertBufferSize_sfMitm(
        m_forward_service.get(), needed_buffer_size.GetPointer()));

    R_SUCCEED();
}

Result SslConnectionImpl::SetSessionCacheMode(
    const ams::ssl::sf::SessionCacheMode &mode) {
    R_TRY(sslConnectionSetSessionCacheMode_sfMitm(m_forward_service.get(),
                                                  static_cast<u32>(mode)));

    R_SUCCEED();
}

Result SslConnectionImpl::GetSessionCacheMode(
    ams::sf::Out<ams::ssl::sf::SessionCacheMode> mode) {
    R_TRY(sslConnectionGetSessionCacheMode_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(mode.GetPointer())));

    R_SUCCEED();
}

Result SslConnectionImpl::FlushSessionCache() {
    R_TRY(sslConnectionFlushSessionCache_sfMitm(m_forward_service.get()));

    R_SUCCEED();
}

Result SslConnectionImpl::SetRenegotiationMode(
    const ams::ssl::sf::RenegotiationMode &mode) {
    R_TRY(sslConnectionSetRenegotiationMode_sfMitm(m_forward_service.get(),
                                                   static_cast<u32>(mode)));

    R_SUCCEED();
}

Result SslConnectionImpl::GetRenegotiationMode(
    ams::sf::Out<ams::ssl::sf::RenegotiationMode> mode) {
    R_TRY(sslConnectionGetRenegotiationMode_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(mode.GetPointer())));

    R_SUCCEED();
}

Result
SslConnectionImpl::SetOptionReal(bool value,
                                 const ams::ssl::sf::OptionType &option) {
    R_TRY(sslConnectionSetOption_sfMitm(m_forward_service.get(), value,
                                        static_cast<u32>(option)));

    R_SUCCEED();
}

Result SslConnectionImpl::SetOption(bool value,
                                    const ams::ssl::sf::OptionType &option) {
    if (g_should_disable_ssl_verification &&
        option == ams::ssl::sf::OptionType::SkipDefaultVerify) {
        m_requested_default_verify = value;
        value =
            true; // force SkipDefaultVerify on, even when requested disabled
    }

    return SetOptionReal(value, option);
}

Result SslConnectionImpl::GetOptionReal(const ams::ssl::sf::OptionType &value,
                                        ams::sf::Out<bool> option) {
    R_TRY(sslConnectionGetOption_sfMitm(
        m_forward_service.get(), static_cast<u32>(value), option.GetPointer()));

    R_SUCCEED();
}

Result SslConnectionImpl::GetOption(const ams::ssl::sf::OptionType &value,
                                    ams::sf::Out<bool> option) {
    bool returned_value;
    R_TRY(sslConnectionGetOption_sfMitm(
        m_forward_service.get(), static_cast<u32>(value), &returned_value));

    if (g_should_disable_ssl_verification &&
        value == ams::ssl::sf::OptionType::SkipDefaultVerify) {
        option.SetValue(m_requested_default_verify);
    } else {
        option.SetValue(returned_value);
    }

    R_SUCCEED();
}

Result SslConnectionImpl::GetVerifyCertErrors(ams::sf::Out<u32> unk0,
                                              ams::sf::Out<u32> unk1,
                                              const ams::sf::OutBuffer &unk2) {
    R_TRY(sslConnectionGetVerifyCertErrors_sfMitm(
        m_forward_service.get(), unk0.GetPointer(), unk1.GetPointer(),
        unk2.GetPointer(), unk2.GetSize()));

    R_SUCCEED();
}

Result SslConnectionImpl::GetCipherInfo(u32 unk0,
                                        const ams::sf::OutBuffer &cipher_info) {
    R_TRY(sslConnectionGetCipherInfo_sfMitm(m_forward_service.get(), unk0,
                                            cipher_info.GetPointer(),
                                            cipher_info.GetSize()));

    R_SUCCEED();
}

Result
SslConnectionImpl::SetNextAlpnProto(const ams::sf::InBuffer &alpn_proto) {
    R_TRY(sslConnectionSetNextAlpnProto_sfMitm(m_forward_service.get(),
                                               alpn_proto.GetPointer(),
                                               alpn_proto.GetSize()));

    R_SUCCEED();
}

Result SslConnectionImpl::GetNextAlpnProto(
    ams::sf::Out<ams::ssl::sf::AlpnProtoState> state,
    ams::sf::Out<u32> alpn_proto_out_size,
    const ams::sf::OutBuffer &alpn_proto) {
    R_TRY(sslConnectionGetNextAlpnProto_sfMitm(
        m_forward_service.get(), reinterpret_cast<u32 *>(state.GetPointer()),
        alpn_proto_out_size.GetPointer(), alpn_proto.GetPointer(),
        alpn_proto.GetSize()));

    R_SUCCEED();
}

Result
SslConnectionImpl::SetDtlsSocketDescriptor(u32 sock_fd,
                                           const ams::sf::InBuffer &sock_addr,
                                           ams::sf::Out<u32> out_sock_fd) {
    R_TRY(sslConnectionSetDtlsSocketDescriptor_sfMitm(
        m_forward_service.get(), sock_fd, sock_addr.GetPointer(),
        sock_addr.GetSize(), out_sock_fd.GetPointer()));

    R_SUCCEED();
}

Result
SslConnectionImpl::GetDtlsHandshakeTimeout(const ams::sf::OutBuffer &timespan) {
    R_TRY(sslConnectionGetDtlsHandshakeTimeout_sfMitm(
        m_forward_service.get(), timespan.GetPointer(), timespan.GetSize()));

    R_SUCCEED();
}

Result
SslConnectionImpl::SetPrivateOptionReal(const ams::ssl::sf::OptionType &option,
                                        u32 value) {
    return sslConnectionSetPrivateOption_sfMitm(m_forward_service.get(), value,
                                                static_cast<u32>(option));
}

Result
SslConnectionImpl::SetPrivateOption(const ams::ssl::sf::OptionType &option,
                                    u32 value) {
    if (g_should_disable_ssl_verification &&
        option == ams::ssl::sf::OptionType::SkipDefaultVerify) {
        m_requested_default_verify = value;
        value = 1; // force SkipDefaultVerify on, even when requested disabled
    }

    return SetPrivateOptionReal(option, value);
}

Result SslConnectionImpl::SetSrtpCiphers(const ams::sf::InBuffer &ciphers) {
    R_TRY(sslConnectionSetSrtpCiphers_sfMitm(
        m_forward_service.get(), ciphers.GetPointer(), ciphers.GetSize()));

    R_SUCCEED();
}

Result SslConnectionImpl::GetSrtpCipher(ams::sf::Out<u16> cipher) {
    R_TRY(sslConnectionGetSrtpCipher_sfMitm(m_forward_service.get(),
                                            cipher.GetPointer()));

    R_SUCCEED();
}

Result
SslConnectionImpl::ExportKeyingMaterial(const ams::sf::InBuffer &label,
                                        const ams::sf::InBuffer &context,
                                        const ams::sf::OutBuffer &material) {
    R_TRY(sslConnectionExportKeyingMaterial_sfMitm(
        m_forward_service.get(), label.GetPointer(), label.GetSize(),
        context.GetPointer(), context.GetSize(), material.GetPointer(),
        material.GetSize()));

    R_SUCCEED();
}

Result SslConnectionImpl::SetIoTimeout(u32 timeout) {
    R_TRY(sslConnectionSetIoTimeout_sfMitm(m_forward_service.get(), timeout));

    R_SUCCEED();
}

Result SslConnectionImpl::GetIoTimeout(ams::sf::Out<u32> timeout) {
    R_TRY(sslConnectionGetIoTimeout_sfMitm(m_forward_service.get(),
                                           timeout.GetPointer()));

    R_SUCCEED();
}

Result
SslConnectionImpl::GetSessionTicket(const ams::sf::OutBuffer &session_ticket,
                                    ams::sf::Out<u32> out_session_ticket_size) {
    R_TRY(sslConnectionGetSessionTicket_sfMitm(
        m_forward_service.get(), session_ticket.GetPointer(),
        session_ticket.GetSize(), out_session_ticket_size.GetPointer()));

    R_SUCCEED();
}

Result
SslConnectionImpl::SetSessionTicket(const ams::sf::InBuffer &session_ticket) {
    R_TRY(sslConnectionSetSessionTicket_sfMitm(m_forward_service.get(),
                                               session_ticket.GetPointer(),
                                               session_ticket.GetSize()));

    R_SUCCEED();
}

} // namespace ams::ssl::sf::impl
