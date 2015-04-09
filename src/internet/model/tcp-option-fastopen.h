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

#ifndef TCP_OPTION_FAST_OPEN_H
#define TCP_OPTION_FAST_OPEN_H

#include "ns3/tcp-option.h"

namespace ns3 {

/**
 * Defines the TCP option of kind 34 (fast open option) as in \RFC{7413}
 */

class TcpOptionFastOpen : public TcpOption
{
public:
  TcpOptionFastOpen ();
  virtual ~TcpOptionFastOpen ();

  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;

  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);

  virtual uint8_t GetKind (void) const;
  virtual uint32_t GetSerializedSize (void) const;

  /**
   * \brief Get the cookie stored in the Option
   * \return the cookie
   */
  uint32_t GetCookie (void);

  /**
   * \brief Set the cookie stored in the Option
   * \param cookie the cookie
   */
  void SetCookie (uint32_t cookie);

protected:
  uint32_t m_cookie; //!< cookie
};

} // namespace ns3

#endif /* TCP_OPTION_FAST_OPEN */
