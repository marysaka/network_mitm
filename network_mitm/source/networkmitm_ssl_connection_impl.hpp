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
#include "networkmitm_ssl_types.hpp"
#include "networkmitm_utils.hpp"
#include "impl/pcap/pcap_file_writer.hpp"
#include "impl/pcap/pcap_utils.hpp"

using namespace ams::ssl::mitm::pcap;

#define AMS_INTERFACE_ISSLCONNECTION_INFO(C, H) \
    AMS_SF_METHOD_INFO(C, H, 0, Result, SetSocketDescriptor, (u32 input_socket_fd, ams::sf::Out<u32> output_socket_fd), (input_socket_fd, output_socket_fd)) \
    AMS_SF_METHOD_INFO(C, H, 1, Result, SetHostName, (const ams::sf::InBuffer &hostname), (hostname)) \
    AMS_SF_METHOD_INFO(C, H, 2, Result, SetVerifyOption, (const ams::ssl::sf::VerifyOption &option), (option)) \
    AMS_SF_METHOD_INFO(C, H, 3, Result, SetIoMode, (const ams::ssl::sf::IoMode &mode), (mode)) \
    AMS_SF_METHOD_INFO(C, H, 4, Result, GetSocketDescriptor, (ams::sf::Out<u32> socket_fd), (socket_fd)) \
    AMS_SF_METHOD_INFO(C, H, 5, Result, GetHostName, (ams::sf::Out<u32> hostname_length, const ams::sf::OutBuffer &hostname), (hostname_length, hostname)) \
    AMS_SF_METHOD_INFO(C, H, 6, Result, GetVerifyOption, (ams::sf::Out<ams::ssl::sf::VerifyOption> option), (option)) \
    AMS_SF_METHOD_INFO(C, H, 7, Result, GetIoMode, (ams::sf::Out<ams::ssl::sf::IoMode> mode), (mode)) \
    AMS_SF_METHOD_INFO(C, H, 8, Result, DoHandshake, (), ()) \
    AMS_SF_METHOD_INFO(C, H, 9, Result, DoHandshakeGetServerCert, (ams::sf::Out<u32> buffer_size, ams::sf::Out<u32> certificates_count, const ams::sf::OutBuffer &server_cert_buffer), (buffer_size, certificates_count, server_cert_buffer)) \
    AMS_SF_METHOD_INFO(C, H, 10, Result, Read, (ams::sf::Out<u32> read_count, const ams::sf::OutBuffer &buffer), (read_count, buffer)) \
    AMS_SF_METHOD_INFO(C, H, 11, Result, Write, (const ams::sf::InBuffer &buffer, ams::sf::Out<u32> write_count), (buffer, write_count)) \
    AMS_SF_METHOD_INFO(C, H, 12, Result, Pending, (ams::sf::Out<u32> pending_count), (pending_count)) \
    AMS_SF_METHOD_INFO(C, H, 13, Result, Peek, (ams::sf::Out<u32> peek_count, const ams::sf::OutBuffer &buffer), (peek_count, buffer)) \
    AMS_SF_METHOD_INFO(C, H, 14, Result, Poll, (const ams::ssl::sf::PollEvent &poll_event, u32 timeout, ams::sf::Out<ams::ssl::sf::PollEvent> out_poll_event), (poll_event, timeout, out_poll_event)) \
    AMS_SF_METHOD_INFO(C, H, 15, Result, GetVerifyCertError, (), ()) \
    AMS_SF_METHOD_INFO(C, H, 16, Result, GetNeededServerCertBufferSize, (ams::sf::Out<u32> needed_buffer_size), (needed_buffer_size)) \
    AMS_SF_METHOD_INFO(C, H, 17, Result, SetSessionCacheMode, (const ams::ssl::sf::SessionCacheMode &mode), (mode)) \
    AMS_SF_METHOD_INFO(C, H, 18, Result, GetSessionCacheMode, (ams::sf::Out<ams::ssl::sf::SessionCacheMode> mode), (mode)) \
    AMS_SF_METHOD_INFO(C, H, 19, Result, FlushSessionCache, (), ()) \
    AMS_SF_METHOD_INFO(C, H, 20, Result, SetRenegotiationMode, (const ams::ssl::sf::RenegotiationMode &mode), (mode)) \
    AMS_SF_METHOD_INFO(C, H, 21, Result, GetRenegotiationMode, (ams::sf::Out<ams::ssl::sf::RenegotiationMode> mode), (mode)) \
    AMS_SF_METHOD_INFO(C, H, 22, Result, SetOption, (bool value, const ams::ssl::sf::OptionType &option), (value, option)) \
    AMS_SF_METHOD_INFO(C, H, 23, Result, GetOption, (const ams::ssl::sf::OptionType &value, ams::sf::Out<bool> option), (value, option)) \
    AMS_SF_METHOD_INFO(C, H, 24, Result, GetVerifyCertErrors, (ams::sf::Out<u32> unk0, ams::sf::Out<u32> unk1, const ams::sf::OutBuffer &unk2), (unk0, unk1, unk2)) \
    AMS_SF_METHOD_INFO(C, H, 25, Result, GetCipherInfo, (u32 unk0, const ams::sf::OutBuffer &cipher_info), (unk0, cipher_info), hos::Version_4_0_0) \
    AMS_SF_METHOD_INFO(C, H, 26, Result, SetNextAlpnProto, (const ams::sf::InBuffer &alpn_proto), (alpn_proto), hos::Version_9_0_0) \
    AMS_SF_METHOD_INFO(C, H, 27, Result, GetNextAlpnProto, (ams::sf::Out<ams::ssl::sf::AlpnProtoState> state, ams::sf::Out<u32> alpn_proto_out_size, const ams::sf::OutBuffer &alpn_proto), (state, alpn_proto_out_size, alpn_proto), hos::Version_9_0_0) \
    AMS_SF_METHOD_INFO(C, H, 28, Result, SetDtlsSocketDescriptor, (u32 sock_fd, const ams::sf::InBuffer &sock_addr, ams::sf::Out<u32> out_sock_fd), (sock_fd, sock_addr, out_sock_fd), hos::Version_16_0_0) \
    AMS_SF_METHOD_INFO(C, H, 29, Result, GetDtlsHandshakeTimeout, (const ams::sf::OutBuffer &timespan), (timespan), hos::Version_16_0_0) \
    AMS_SF_METHOD_INFO(C, H, 30, Result, SetPrivateOption, (const ams::ssl::sf::OptionType &option, u32 value), (option, value), hos::Version_16_0_0) \
    AMS_SF_METHOD_INFO(C, H, 31, Result, SetSrtpCiphers, (const ams::sf::InBuffer &ciphers), (ciphers), hos::Version_16_0_0) \
    AMS_SF_METHOD_INFO(C, H, 32, Result, GetSrtpCipher, (ams::sf::Out<u16> cipher), (cipher), hos::Version_16_0_0) \
    AMS_SF_METHOD_INFO(C, H, 33, Result, ExportKeyingMaterial, (const ams::sf::InBuffer &label, const ams::sf::InBuffer &context, const ams::sf::OutBuffer &material), (label, context, material), hos::Version_16_0_0) \
    AMS_SF_METHOD_INFO(C, H, 34, Result, SetIoTimeout, (u32 timeout), (timeout), hos::Version_16_0_0) \
    AMS_SF_METHOD_INFO(C, H, 35, Result, GetIoTimeout, (ams::sf::Out<u32> timeout), (timeout), hos::Version_16_0_0)

AMS_SF_DEFINE_INTERFACE(ams::ssl::sf, ISslConnection, AMS_INTERFACE_ISSLCONNECTION_INFO, 0xA9B8D9AA)


namespace ams::ssl::sf::impl {
    class SslConnectionImpl {
        protected:
            std::shared_ptr<::Service> m_forward_service;
            sm::MitmProcessInfo m_client_info;
            PcapFileWriter *m_writer;
            ams::ssl::sf::VerifyOption m_requested_option = (ams::ssl::sf::VerifyOption)3;
            bool m_requested_default_verify;
        public:
            SslConnectionImpl(std::shared_ptr<::Service> &&s,
                            const sm::MitmProcessInfo &c, PcapFileWriter *writter)
                : m_forward_service(std::move(s)), m_client_info(c), m_writer(writter) {
                if (g_should_disable_ssl_verification) {
                    Result res;
                    if (R_FAILED(
                            res = SetOptionReal(
                                true, ams::ssl::sf::OptionType::SkipDefaultVerify))) {
                        AMS_LOG("Failed to set SkipDefaultVerify! %d-%d\n",
                                res.GetModule() + 2000, res.GetValue());
                    }
                    if (R_FAILED(res = SetVerifyOptionReal(
                                    static_cast<ams::ssl::sf::VerifyOption>(0)))) {
                        AMS_LOG("Failed to SetVerifyOptionReal(0)! %d-%d\n",
                                res.GetModule() + 2000, res.GetValue());
                    }
                }
            }
            ~SslConnectionImpl() {
                if (m_writer != nullptr) {
                    delete m_writer;
                }
            }

            Result SetSocketDescriptor(u32 input_socket_fd, ams::sf::Out<u32> output_socket_fd);
            Result SetHostName(const ams::sf::InBuffer &hostname);
            Result SetVerifyOption(const ams::ssl::sf::VerifyOption &option);
            Result SetIoMode(const ams::ssl::sf::IoMode &mode);
            Result GetSocketDescriptor(ams::sf::Out<u32> socket_fd);
            Result GetHostName(ams::sf::Out<u32> hostname_length, const ams::sf::OutBuffer &hostname);
            Result GetVerifyOption(ams::sf::Out<ams::ssl::sf::VerifyOption> option);
            Result GetIoMode(ams::sf::Out<ams::ssl::sf::IoMode> mode);
            Result DoHandshake();
            Result DoHandshakeGetServerCert(ams::sf::Out<u32> buffer_size, ams::sf::Out<u32> certificates_count, const ams::sf::OutBuffer &server_cert_buffer);
            Result Read(ams::sf::Out<u32> read_count, const ams::sf::OutBuffer &buffer);
            Result Write(const ams::sf::InBuffer &buffer, ams::sf::Out<u32> write_count);
            Result Pending(ams::sf::Out<u32> pending_count);
            Result Peek(ams::sf::Out<u32> peek_count, const ams::sf::OutBuffer &buffer);
            Result Poll(const ams::ssl::sf::PollEvent &poll_event, u32 timeout, ams::sf::Out<ams::ssl::sf::PollEvent> out_poll_event);
            Result GetVerifyCertError();
            Result GetNeededServerCertBufferSize(ams::sf::Out<u32> needed_buffer_size);
            Result SetSessionCacheMode(const ams::ssl::sf::SessionCacheMode &mode);
            Result GetSessionCacheMode(ams::sf::Out<ams::ssl::sf::SessionCacheMode> mode);
            Result FlushSessionCache();
            Result SetRenegotiationMode(const ams::ssl::sf::RenegotiationMode &mode);
            Result GetRenegotiationMode(ams::sf::Out<ams::ssl::sf::RenegotiationMode> mode);
            Result SetOption(bool value, const ams::ssl::sf::OptionType &option);
            Result GetOption(const ams::ssl::sf::OptionType &value, ams::sf::Out<bool> option);
            Result GetVerifyCertErrors(ams::sf::Out<u32> unk0, ams::sf::Out<u32> unk1, const ams::sf::OutBuffer &unk2);
            Result GetCipherInfo(u32 unk0, const ams::sf::OutBuffer &cipher_info);
            Result SetNextAlpnProto(const ams::sf::InBuffer &alpn_proto);
            Result GetNextAlpnProto(ams::sf::Out<ams::ssl::sf::AlpnProtoState> state, ams::sf::Out<u32> alpn_proto_out_size, const ams::sf::OutBuffer &alpn_proto);
            Result SetDtlsSocketDescriptor(u32 sock_fd, const ams::sf::InBuffer &sock_addr, ams::sf::Out<u32> out_sock_fd);
            Result GetDtlsHandshakeTimeout(const ams::sf::OutBuffer &timespan);
            Result SetPrivateOption(const ams::ssl::sf::OptionType &option, u32 value);
            Result SetSrtpCiphers(const ams::sf::InBuffer &ciphers);
            Result GetSrtpCipher(ams::sf::Out<u16> cipher);
            Result ExportKeyingMaterial(const ams::sf::InBuffer &label, const ams::sf::InBuffer &context, const ams::sf::OutBuffer &material);
            Result SetIoTimeout(u32 timeout);
            Result GetIoTimeout(ams::sf::Out<u32> timeout);

            Result SetOptionReal(bool value, const ams::ssl::sf::OptionType &option);
            Result GetOptionReal(const ams::ssl::sf::OptionType &value, ams::sf::Out<bool> option);
            Result SetVerifyOptionReal(const ams::ssl::sf::VerifyOption &option);
            Result SetPrivateOptionReal(const ams::ssl::sf::OptionType &option, u32 value);
    };

    static_assert(ams::ssl::sf::IsISslConnection<ams::ssl::sf::impl::SslConnectionImpl>);
}
