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

#ifndef TCP_FASTOPEN_H
#define TCP_FASTOPEN_H

#include "ns3/packet.h"
#include "tcp-header.h"
#include "tcp-socket-base.h"
#include "tcp-newreno.h"

namespace ns3 {

/**
 * \ingroup socket
 * \ingroup tcp
 *
 * \brief An implementation of a stream socket using TCP.
 *
 * This class builds upon the NewReno implementation of TCP, as of \RFC{2582}, adding Fast Open
 * functionality (\RFC{7413})
 */
class TcpFastOpen : public TcpNewReno {
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId(void);

  /**
   * Create an unbound tcp socket.
   */
  TcpFastOpen(void);

  /**
   * \brief Copy constructor
   * \param sock the object to copy
   */
  TcpFastOpen(const TcpFastOpen &sock);

protected:
  // From TcpSocketBase

  virtual void ProcessSynSent (Ptr<Packet> packet, const TcpHeader& tcpHeader);

  virtual void ProcessSynRcvd (Ptr<Packet> packet, const TcpHeader& tcpHeader,
                               const Address& fromAddress, const Address& toAddress);

  virtual void ProcessListen (Ptr<Packet> packet, const TcpHeader& tcpHeader,
                      const Address& fromAddress, const Address& toAddress);

  virtual void CompleteFork (Ptr<Packet> p, const TcpHeader& tcpHeader, const Address& fromAddress,
                             const Address& toAddress);

  virtual Ptr<TcpSocketBase> Fork (void);

  virtual void AddOptions (TcpHeader& tcpHeader);

  virtual void ProcessEstablished (Ptr<Packet> packet, const TcpHeader& tcpHeader);

  virtual int DoConnect(const Address & address);

  uint32_t GenerateCookie (const Address& address);

  bool IsValidCookie (uint32_t cookie, const Address& address);

private:
  uint32_t m_cookie;
};

} // namespace ns3

#endif /* TCP_FASTOPEN_H */
