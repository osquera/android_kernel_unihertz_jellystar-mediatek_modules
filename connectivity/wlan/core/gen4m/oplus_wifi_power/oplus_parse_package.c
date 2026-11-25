/******************************************************************************
** Copyright (C), 2019-2029, Oplus Mobile Comm Corp., Ltd
** File: - oplus_prase_package.c
** Description: prase wake up package type
**
** Version: 1.0
** Date : 2023/06/01
** CONNECTIVITY.WIFI.HARDWARE.26106
** TAG: OPLUS_FEATURE_WIFI_HARDWARE_POWER
** ------------------------------- Revision History: ----------------------------
** <author>  wuguotian                    <data>        <version>       <desc>
** ------------------------------------------------------------------------------
**CONNECTIVITY.WIFI.HARDWARE.POWER.26106 2023/06/01        1.0    OPLUS_FEATURE_WIFI_HARDWARE_POWER
*******************************************************************************/

#include "oplus_parse_package.h"
#include "precomp.h"

uint16_t oplusStatsParseUDPInfo(struct sk_buff *skb, uint8_t *pucEthBody)
{
    uint8_t *pucUdp = &pucEthBody[20];
    uint16_t u2UdpDstPort;
    uint16_t u2UdpSrcPort;
    uint16_t packageType = IP_PRO_UDP;

    u2UdpDstPort = (pucUdp[2] << 8) | pucUdp[3];
    u2UdpSrcPort = (pucUdp[0] << 8) | pucUdp[1];
    if (u2UdpDstPort == UDP_PORT_DHCPS || u2UdpDstPort == UDP_PORT_DHCPC) {
        packageType = UDP_PORT_DHCPS;
    } else if (u2UdpSrcPort == UDP_PORT_DNS ||
        u2UdpDstPort == UDP_PORT_DNS) {
        packageType = UDP_PORT_DNS;
    }
    return packageType;
}

uint16_t oplusStatsParseIPV4Info(struct sk_buff *skb, uint8_t *pucEthBody)
{
    /* IP header without options */
    uint8_t ucIpProto = pucEthBody[9];
    uint8_t ucIpVersion =
        (pucEthBody[0] & IPVH_VERSION_MASK)
            >> IPVH_VERSION_OFFSET;
    uint16_t u2IpId = pucEthBody[4] << 8 | pucEthBody[5];
    uint16_t packageType = ETH_P_IPV4;

    if (ucIpVersion != IPVERSION || !skb || !pucEthBody) {
        return packageType;
    }

    GLUE_SET_PKT_IP_ID(skb, u2IpId);
    switch (ucIpProto) {
        case IP_PRO_ICMP: {
            packageType = IP_PRO_ICMP;
            break;
        }
        case IP_PRO_TCP: {
            packageType = IP_PRO_TCP;
            break;
        }
        case IP_PRO_UDP: {
            packageType = oplusStatsParseUDPInfo(skb, pucEthBody);
        }
    }
    DBGLOG(RX, INFO, "wake ipv4 pkttype is %d\n", packageType);
    return packageType;
}

uint16_t oplusstats_parseipv6udpinfo(struct sk_buff *skb, uint8_t *puc_ipv6body)
{
    struct UDP_HEADER *prUdp;
    uint16_t u2UdpDstPort;
    uint16_t u2UdpSrcPort;
    uint16_t packageType = IP_PRO_UDP;

    /* puc_ipv6body points to IPv6 header (after ETH_HLEN),
     * skb->len includes ETH_HLEN, so we need at least
     * ETH_HLEN + IPV6_HDR_LEN + UDP_HDR_LEN to read UDP header */
    if (!skb || !puc_ipv6body ||
        skb->len < (ETH_HLEN + IPV6_HDR_LEN + UDP_HDR_LEN)) {
        return packageType;
    }

    prUdp = (struct UDP_HEADER *)&puc_ipv6body[IPV6_HDR_LEN];

    u2UdpDstPort = NTOHS(prUdp->u2DstPort);
    u2UdpSrcPort = NTOHS(prUdp->u2SrcPort);

    if (u2UdpSrcPort == IPV6_UDP_PORT_DHCPS ||
        u2UdpSrcPort == IPV6_UDP_PORT_DHCPC) {
        packageType = IPV6_UDP_PORT_DHCPS;
    } else if (u2UdpSrcPort == UDP_PORT_DNS ||
               u2UdpDstPort == UDP_PORT_DNS) {
        packageType = UDP_PORT_DNS;
    } else if (u2UdpSrcPort == UDP_PORT_NTP ||
               u2UdpDstPort == UDP_PORT_NTP) {
        packageType = UDP_PORT_NTP;
    }
    return packageType;
}

uint16_t oplusstats_parseipv6info(struct sk_buff *skb, uint8_t *puc_ethbody)
{
    struct IPV6_HEADER *prIpv6 = (struct IPV6_HEADER *)puc_ethbody;
    uint8_t ucIpVersion = GET_IP_VERSION(puc_ethbody);
    uint8_t ucIpv6Proto;
    uint16_t packageType = ETH_P_IPV6;

    if (ucIpVersion != IP_VERSION_6 || !skb || !puc_ethbody) {
        return packageType;
    }

    ucIpv6Proto = prIpv6->ucNextHeader;

    switch (ucIpv6Proto) {
    case IP_PRO_TCP:
        packageType = IP_PRO_TCP;
        break;

    case IP_PRO_UDP:
        packageType = oplusstats_parseipv6udpinfo(skb, puc_ethbody);
        break;

    case IPV6_PROTOCOL_HOP_BY_HOP:
        packageType = IPV6_PROTOCOL_HOP_BY_HOP;
        break;

    case IPV6_PROTOCOL_ICMPV6: {
        uint16_t u2PayloadLen = NTOHS(prIpv6->u2PayloadLength);
        if (u2PayloadLen < 1) {
            DBGLOG(RX, INFO,
                   "ICMPv6 Payload Length is too small to read ICMPv6 Type\n");
            packageType = IPV6_PROTOCOL_ICMPV6;
            break;
        }
        struct ICMPV6_HEADER *prIcmp6 =
            (struct ICMPV6_HEADER *)prIpv6->aucL4;

        packageType = prIcmp6->ucType;
        break;
    }

    default:
        packageType = ucIpv6Proto;
        break;
    }

    DBGLOG(RX, INFO, "wake ipv6 pkttype is %d (NextHeader=%d)\n",
            packageType, ucIpv6Proto);
    return packageType;
}
