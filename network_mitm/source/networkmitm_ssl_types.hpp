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
#include <vapours.hpp>

namespace ams::ssl::sf {
    enum class AlpnProtoState : u32 {
        NoSupport = 0,
        Negotiated = 1,
        NoOverlap = 2,
        Selected = 3,
        EarlyValue = 4,
    };

    enum class CaCertificateId : u32 {
        NintendoCAG3 = 1,
        NintendoClass2CAG3 = 2,
        AmazonRootCA1 = 1000,
        StarfieldServicesRootCertificateAuthorityG2 = 1001,
        AddTrustExternalCARoot = 1002,
        COMODOCertificationAuthority = 1003,
        UTNDATACorpSGC = 1004,
        UTNUSERFirstHardware = 1005,
        BaltimoreCyberTrustRoot = 1006,
        CybertrustGlobalRoot = 1007,
        VerizonGlobalRootCA = 1008,
        DigiCertAssuredIDRootCA = 1009,
        DigiCertAssuredIDRootG2 = 1010,
        DigiCertGlobalRootCA = 1011,
        DigiCertGlobalRootG2 = 1012,
        DigiCertHighAssuranceEVRootCA = 1013,
        EntrustnetCertificationAuthority2048 = 1014,
        EntrustRootCertificationAuthority = 1015,
        EntrustRootCertificationAuthorityG2 = 1016,
        GeoTrustGlobalCA2 = 1017,
        GeoTrustGlobalCA = 1018,
        GeoTrustPrimaryCertificationAuthorityG3 = 1019,
        GeoTrustPrimaryCertificationAuthority = 1020,
        GlobalSignRootCA = 1021,
        GlobalSignRootCAR2 = 1022,
        GlobalSignRootCAR3 = 1023,
        GoDaddyClass2CertificationAuthority = 1024,
        GoDaddyRootCertificateAuthorityG2 = 1025,
        StarfieldClass2CertificationAuthority = 1026,
        StarfieldRootCertificateAuthorityG2 = 1027,
        ThawtePrimaryRootCAG3 = 1028,
        ThawtePrimaryRootCA = 1029,
        VeriSignClass3PublicPrimaryCertificationAuthorityG3 = 1030,
        VeriSignClass3PublicPrimaryCertificationAuthorityG5 = 1031,
        VeriSignUniversalRootCertificationAuthority = 1032,
        DSTRootCAX3 = 1033,
        USERTrustRSACertificationAuthority = 1034,
        ISRGRootX10 = 1035,
        USERTrustECCCertificationAuthority = 1036,
        COMODORSACertificationAuthority = 1037,
        COMODOECCCertificationAuthority = 1038,
        AmazonRootCA2 = 1039,
        AmazonRootCA3 = 1040,
        AmazonRootCA4 = 1041,
        DigiCertAssuredIDRootG3 = 1042,
        DigiCertGlobalRootG3 = 1043,
        DigiCertTrustedRootG4 = 1044,
        EntrustRootCertificationAuthorityEC1 = 1045,
        EntrustRootCertificationAuthorityG4 = 1046,
        GlobalSignECCRootCAR4 = 1047,
        GlobalSignECCRootCAR5 = 1048,
        GlobalSignECCRootCAR6 = 1049,
        GTSRootR1 = 1050,
        GTSRootR2 = 1051,
        GTSRootR3 = 1052,
        GTSRootR4 = 1053,
        SecurityCommunicationRootCA = 1054,
        GlobalSignRootE4 = 1055,
        GlobalSignRootE4_2 = 1056,
        TTeleSecGlobalRootClass2 = 1057,
        DigiCertTLSECCP384RootG5 = 1058,
        DigiCertTLSRSA4096RootG5 = 1059,
        SslRrNetDevNtdNintendo01 = 32801,
        SslRrNetDevNtdNintendo02 = 32802,
        SslRrNetDevNtdNintendo03 = 32803,
        SslRrNetDevNtdNintendo04 = 32804,
        SslRrNetDevNtdNintendo05 = 32805,
        SslRrNetDevNtdNintendo06 = 32806,
        SslRrNetDevNtdNintendo07 = 32807,
        SslRrNetDevNtdNintendo08 = 32808,
        SslRrNetDevNtdNintendo09 = 32809,
        SslRrNetDevNtdNintendo10 = 32810,
        SslRrNetDevNtdNintendo11 = 32811,
        SslRrNetDevNtdNintendo12 = 32812,
        SslRrNetDevNtdNintendo13 = 32813,
        SslRrNetDevNtdNintendo14 = 32814,
        SslRrNetDevNtdNintendo15 = 32815,
        SslRrNetDevNtdNintendo16 = 32816,
        SslRrNetDevNtdNintendo17 = 32817,
        SslRrNetDevNtdNintendo18 = 32818,
        SslRrNetDevNtdNintendo19 = 32819,
        SslRrNetDevNtdNintendo20 = 32820,
        SslRrNetDevNtdNintendo21 = 32821,
        SslRrNetDevNtdNintendo22 = 32822,
        SslRrNetDevNtdNintendo23 = 32823,
        SslRrNetDevNtdNintendo24 = 32824,
        SslRrNetDevNtdNintendo25 = 32825,
        SslRrNetDevNtdNintendo26 = 32826,
        SslRrNetDevNtdNintendo27 = 32827,
        SslRrNetDevNtdNintendo28 = 32828,
        SslRrNetDevNtdNintendo29 = 32829,
        SslRrNetDevNtdNintendo30 = 32830,
        SslRrNetDevNtdNintendo31 = 32831,
        SslRrNetDevNtdNintendo32 = 32832,
        SslRrNetDevNtdNintendo33 = 32833,
        SslRrNetDevNtdNintendo34 = 32834,
        SslRrNetDevNtdNintendo35 = 32835,
        SslRrNetDevNtdNintendo36 = 32836,
        SslRrNetDevNtdNintendo37 = 32837,
        SslRrNetDevNtdNintendo38 = 32838,
        SslRrNetDevNtdNintendo39 = 32839,
        SslRrNetDevNtdNintendo40 = 32840,
        SslRrNetDevNtdNintendo41 = 32841,
        SslRrNetDevNtdNintendo42 = 32842,
        SslRrNetDevNtdNintendo43 = 32843,
        SslRrNetDevNtdNintendo44 = 32844,
        SslRrNetDevNtdNintendo45 = 32845,
        SslRrNetDevNtdNintendo46 = 32846,
        SslRrNetDevNtdNintendo47 = 32847,
        SslRrNetDevNtdNintendo48 = 32848,
        SslRrNetDevNtdNintendo49 = 32849,
        SslRrNetDevNtdNintendo50 = 32850,
        SslRrNetDevNtdNintendo51 = 32851,
        SslRrNetDevNtdNintendo52 = 32852,
        SslRrNetDevNtdNintendo53 = 32853,
        SslRrNetDevNtdNintendo54 = 32854,
        SslRrNetDevNtdNintendo55 = 32855,
        SslRrNetDevNtdNintendo56 = 32856,
        SslRrNetDevNtdNintendo57 = 32857,
        SslRrNetDevNtdNintendo58 = 32858,
        SslRrNetDevNtdNintendo59 = 32859,
        SslRrNetDevNtdNintendo60 = 32860,
        SslRrNetDevNtdNintendo61 = 32861,
        SslRrNetDevNtdNintendo62 = 32862,
        SslRrNetDevNtdNintendo63 = 32863,
        SslRrNetDevNtdNintendo64 = 32864,
        All = 4294967295,
        NewAll = 4294967294,
    };

    enum class CertificateFormat : u32 {
        Pem = 1,
        Der = 2,
    };

    enum class ContextOption : u32 {
        None = 0,
        CrlImportDateCheckEnable = 1,
    };

    enum class DebugOptionType : u32 {
        AllowDisableVerifyOption = 0,
    };

    enum class FlushSessionCacheOptionType : u32 {
        SingleHost = 0,
        AllHosts = 0,
    };

    enum class InternalPki : u32 {
        None = 0,
        DeviceClientCertDefault = 0,
    };

    enum class IoMode : u32 {
        Blocking = 1,
        NonBlocking = 1,
    };

    enum class OptionType : u32 {
        DoNotCloseSocket = 0,
        GetServerCertChain = 1,
        SkipDefaultVerify = 2,
        EnableAlpn = 3,
    };

    enum class PollEvent : u32 {
        Read = 0,
        Write = 1,
        Except = 2,
    };

    enum class RenegotiationMode : u32 {
        None = 0,
        Secure = 1,
    };

    enum class SessionCacheMode : u32 {
        None = 0,
        SessionId = 1,
        SessionTicket = 2,
    };

    enum class SslVersion : u32 {
        Auto = 1,
        TlsV10 = 8,
        TlsV11 = 16,
        TlsV12 = 32,
        TlsV13 = 64,
    };

    enum class VerifyOption : u32 {
        PeerCa = 0,
        HostName = 1,
        DateCheck = 2,
        EvCertPartial = 3,
        EvPolicyOid = 4,
        EvCertFingerprint = 5,
    };

}
