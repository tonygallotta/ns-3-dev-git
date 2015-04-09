/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 Adrian Sai-wah Tam
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Tony Gallotta <anthony.gallotta@gmail.com>
 */

#define NS_LOG_APPEND_CONTEXT \
  if (m_node) { std::clog << Simulator::Now ().GetSeconds () << " [node " << m_node->GetId () << "] "; }

#include "tcp-fastopen.h"
#include "tcp-header.h"
#include "ns3/tcp-option-fastopen.h"
#include "ns3/simulator.h"
#include "ns3/abort.h"
#include "ns3/node.h"
#include "ns3/log.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/simulator.h"
#include "ns3/abort.h"
#include "ns3/node.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/tcp-l4-protocol.h"

#include <math.h>
#include <algorithm>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TcpFastOpen");

NS_OBJECT_ENSURE_REGISTERED (TcpFastOpen);

TypeId
TcpFastOpen::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpFastOpen")
    .SetParent<TcpSocketBase> ()
    .SetGroupName ("Internet")
    .AddConstructor<TcpFastOpen> ()
 ;
  return tid;
}

TcpFastOpen::TcpFastOpen (void) : m_cookie (0)
{
  NS_LOG_FUNCTION (this);
}

TcpFastOpen::TcpFastOpen (const TcpFastOpen& sock)
  : TcpNewReno (sock), m_cookie (0)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
}

void
TcpFastOpen::ProcessSynSent (Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags () & ~(TcpHeader::PSH | TcpHeader::URG);
  NS_LOG_LOGIC ("Processing SYN Sent with flags " << int(tcpflags));

  if (tcpflags == (TcpHeader::SYN | TcpHeader::ACK) && tcpHeader.HasOption (TcpOption::FAST_OPEN)) {
    if (m_cookie == 0) {
      // save the cookie!
      Ptr<TcpOptionFastOpen> option = DynamicCast<TcpOptionFastOpen> (tcpHeader.GetOption (TcpOption::FAST_OPEN));
      m_cookie = option->GetCookie ();
      NS_LOG_INFO ("Cookie received: " << m_cookie);
    }
    NS_LOG_INFO ("SYN_SENT -> ESTABLISHED");
    m_state = ESTABLISHED;
    m_connected = true;
    m_retxEvent.Cancel ();
    m_rxBuffer->SetNextRxSequence (tcpHeader.GetSequenceNumber () + SequenceNumber32 (1));
    m_delAckCount = m_delAckMaxCount;
    m_highTxMark = ++m_nextTxSequence;
    m_txBuffer->SetHeadSequence (m_nextTxSequence);
    ReceivedData (packet, tcpHeader);
    SendPendingData (m_connected);
    Simulator::ScheduleNow (&TcpFastOpen::ConnectionSucceeded, this);
  } else {
    TcpSocketBase::ProcessSynSent (packet, tcpHeader);
  }
}

void
TcpFastOpen::ProcessSynRcvd (Ptr<Packet> packet, const TcpHeader& tcpHeader,
    const Address& fromAddress, const Address& toAddress)
{
  if (tcpHeader.HasOption (TcpOption::FAST_OPEN)) {
    Ptr<TcpOptionFastOpen> option = DynamicCast<TcpOptionFastOpen> (tcpHeader.GetOption (TcpOption::FAST_OPEN));
    uint32_t cookie = option->GetCookie ();
    if (IsValidCookie(cookie, fromAddress)) {
      // valid cookie, I can accept data if they sent me some
      ReceivedData (packet, tcpHeader);
    }
  }
  TcpSocketBase::ProcessSynRcvd (packet, tcpHeader, fromAddress, toAddress);
}

void
TcpFastOpen::CompleteFork (Ptr<Packet> p, const TcpHeader& h,
                            const Address& fromAddress, const Address& toAddress)
{
    // TcpSocketBase::CompleteFork(p, h, fromAddress, toAddress);
    // return;
    // Get port and address from peer (connecting host)
    if (InetSocketAddress::IsMatchingType (toAddress))
        {
            m_endPoint = m_tcp->Allocate (InetSocketAddress::ConvertFrom (toAddress).GetIpv4 (),
                                          InetSocketAddress::ConvertFrom (toAddress).GetPort (),
                                          InetSocketAddress::ConvertFrom (fromAddress).GetIpv4 (),
                                          InetSocketAddress::ConvertFrom (fromAddress).GetPort ());
            m_endPoint6 = 0;
        }
    else if (Inet6SocketAddress::IsMatchingType (toAddress))
        {
            m_endPoint6 = m_tcp->Allocate6 (Inet6SocketAddress::ConvertFrom (toAddress).GetIpv6 (),
                                            Inet6SocketAddress::ConvertFrom (toAddress).GetPort (),
                                            Inet6SocketAddress::ConvertFrom (fromAddress).GetIpv6 (),
                                            Inet6SocketAddress::ConvertFrom (fromAddress).GetPort ());
            m_endPoint = 0;
        }
    m_tcp->m_sockets.push_back (this);

    m_state = SYN_RCVD;
    m_cnCount = m_cnRetries;
    SetupCallback ();
    uint8_t flags = (TcpHeader::SYN | TcpHeader::ACK);

    if (h.HasOption(TcpOption::FAST_OPEN)) {
      // Client has a cookie, send a SYN+ACK with data in it
      Ptr<TcpOptionFastOpen> option = DynamicCast<TcpOptionFastOpen> (h.GetOption (TcpOption::FAST_OPEN));
      if (IsValidCookie (option->GetCookie (), fromAddress)) {
        uint32_t w = AvailableWindow ();
        uint32_t s = std::min (w, m_segmentSize);  // Send no more than window
        NS_LOG_LOGIC ("TcpFastOpen " << this << " SendPendingData" <<
                    " w " << w <<
                    " rxwin " << m_rWnd <<
                    " segsize " << m_segmentSize <<
                    " nextTxSeq " << m_nextTxSequence <<
                    " highestRxAck " << m_txBuffer->HeadSequence () <<
                    " pd->Size " << m_txBuffer->Size () <<
                    " pd->SFS " << m_txBuffer->SizeFromSequence (m_nextTxSequence));
        // Stop sending if we need to wait for a larger Tx window (prevent silly window syndrome)
        if (w < m_segmentSize && m_txBuffer->SizeFromSequence (m_nextTxSequence) > w)
          {
            return; // No more
          }
        uint32_t sz = SendDataPacket (m_nextTxSequence, s, flags);
        m_nextTxSequence += sz;                     // Advance next tx sequence
        return;
      }
    }
    // If we've made it here they didn't have a cookie, or it was invalid.
    // Give them a cookie and send a regular SYN-ACK
    m_cookie = GenerateCookie(fromAddress);
    NS_LOG_INFO ("No cookie, just sending a regular SYN-ACK");
    NS_LOG_INFO ("finish data fork: LISTEN -> SYN_RCVD");
    m_state = SYN_RCVD;
    m_cnCount = m_cnRetries;
    SetupCallback ();
    // Set the sequence number and send SYN+ACK
    m_rxBuffer->SetNextRxSequence (h.GetSequenceNumber () + SequenceNumber32 (1));

    SendEmptyPacket (flags);
}

void
TcpFastOpen::ProcessListen (Ptr<Packet> packet, const TcpHeader& tcpHeader,
                              const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION (this << tcpHeader);

  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags () & ~(TcpHeader::PSH | TcpHeader::URG);

  // Fork a socket if received a SYN. Do nothing otherwise.
  // C.f.: the LISTEN part in tcp_v4_do_rcv() in tcp_ipv4.c in Linux kernel
  if (tcpflags != TcpHeader::SYN)
    {
      return;
    }

  // Call socket's notify function to let the server app know we got a SYN
  // If the server app refuses the connection, do nothing
  if (!NotifyConnectionRequest (fromAddress))
    {
      return;
    }
  // We may not have given this client a cookie yet - set the member variable
  // so it's included in the headers
  m_cookie = GenerateCookie(fromAddress);
  Ptr<TcpFastOpen> newSock = CopyObject<TcpFastOpen> (this);
  NS_LOG_LOGIC ("Cloned a TcpFastOpen " << newSock);
  Simulator::ScheduleNow (&TcpFastOpen::CompleteFork, newSock,
                          packet, tcpHeader, fromAddress, toAddress);
}

Ptr<TcpSocketBase>
TcpFastOpen::Fork (void)
{
  return CopyObject<TcpFastOpen> (this);
}

uint32_t
TcpFastOpen::GenerateCookie(const Address& address)
{ // dumb / insecure implementation, just grabs 4 bytes from the IP address
  uint8_t buf[32];
  address.CopyTo(buf);
  return buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

bool
TcpFastOpen::IsValidCookie(uint32_t cookie, const Address& address)
{
  return cookie == GenerateCookie (address);
}

void
TcpFastOpen::AddOptions (TcpHeader& header)
{
  NS_LOG_FUNCTION (this << header);
  TcpSocketBase::AddOptions(header);
  NS_LOG_INFO ("adding options - my cookie is " << m_cookie);
  if (m_cookie > 0) {
    // I have a cookie, include it in the headers
    Ptr<TcpOptionFastOpen> option = CreateObject<TcpOptionFastOpen> ();
    option->SetCookie(m_cookie);
    header.AppendOption(option);
  }
}

int
TcpFastOpen::DoConnect (const Address & address)
{
  NS_LOG_FUNCTION (this);
  // A new connection is allowed only if this socket does not have a connection
  if (m_state == CLOSED || m_state == LISTEN || m_state == SYN_SENT || m_state == LAST_ACK || m_state == CLOSE_WAIT)
    { // if i have a cookie i can send data in the SYN
      if (m_cookie > 0) {
        uint32_t w = AvailableWindow ();
        uint32_t s = std::min (w, m_segmentSize);
        uint8_t flags = TcpHeader::SYN;
        uint32_t sz = SendDataPacket (m_nextTxSequence, s, flags);
        m_nextTxSequence += sz;                     // Advance next tx sequence
      }
      else {
        SendEmptyPacket (TcpHeader::SYN);
      }
      NS_LOG_INFO (TcpStateName[m_state] << " -> SYN_SENT");
      m_state = SYN_SENT;
    }
  else if (m_state != TIME_WAIT)
    { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
      // exists. We send RST, tear down everything, and close this socket.
      SendRST ();
      CloseAndNotify ();
    }
  return 0;
}

void
TcpFastOpen::ProcessEstablished (Ptr<Packet> packet, const TcpHeader& tcpHeader) {
    // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags () & ~(TcpHeader::PSH | TcpHeader::URG);

  if (tcpflags == (TcpHeader::SYN | TcpHeader::ACK))
    { // Might have some data
      ReceivedData (packet, tcpHeader);
      if (m_rxBuffer->Finished ())
        {
          PeerClose (packet, tcpHeader);
        }
    }
  else
    {
      TcpSocketBase::ProcessEstablished (packet, tcpHeader);
    }
}

} // namespace ns3
