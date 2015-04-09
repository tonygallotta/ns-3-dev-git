/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 Adrian Sai-wah Tam
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

#include "tcp-option-fastopen.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TcpOptionFastOpen");

NS_OBJECT_ENSURE_REGISTERED (TcpOptionFastOpen);

TcpOptionFastOpen::TcpOptionFastOpen ()
  : TcpOption (),
    m_cookie (0)
{
}

TcpOptionFastOpen::~TcpOptionFastOpen ()
{
}

TypeId
TcpOptionFastOpen::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpOptionFastOpen")
    .SetParent<TcpOption> ()
    .SetGroupName ("Internet")
    .AddConstructor<TcpOptionFastOpen> ()
  ;
  return tid;
}

TypeId
TcpOptionFastOpen::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
TcpOptionFastOpen::Print (std::ostream &os) const
{
  os << m_cookie;
}

uint32_t
TcpOptionFastOpen::GetSerializedSize (void) const
{
  return 6;
}

void
TcpOptionFastOpen::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (GetKind ()); // Kind: 1B
  i.WriteU8 (6); // Length: 1B
  i.WriteHtonU32 (m_cookie); // cookie: 4B
}

uint32_t
TcpOptionFastOpen::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  uint8_t readKind = i.ReadU8 ();
  if (readKind != GetKind ())
    {
      NS_LOG_WARN ("Malformed Fast Open option");
      return 0;
    }

  uint8_t size = i.ReadU8 ();
  if (size != 6)
    {
      NS_LOG_WARN ("Malformed Fast Open option");
      return 0;
    }
  m_cookie = i.ReadNtohU32 ();
  return GetSerializedSize ();
}

uint8_t
TcpOptionFastOpen::GetKind (void) const
{
  return TcpOption::FAST_OPEN;
}

uint32_t
TcpOptionFastOpen::GetCookie (void)
{
  return m_cookie;
}

void
TcpOptionFastOpen::SetCookie (uint32_t cookie)
{
  m_cookie = cookie;
}

} // namespace ns3
