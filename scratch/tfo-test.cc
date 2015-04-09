/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
 */

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("TCPFastOpenTest");

static int packetsDropped = 0;

// ===========================================================================
//
//         node 0                 node 1
//   +----------------+    +----------------+
//   |    ns-3 TCP    |    |    ns-3 TCP    |
//   +----------------+    +----------------+
//   |    10.1.1.1    |    |    10.1.1.2    |
//   +----------------+    +----------------+
//   | point-to-point |    | point-to-point |
//   +----------------+    +----------------+
//           |                     |
//           +---------------------+
//                10 Mbps, 2 ms
//
//
// Example for testing throughput of TCP Fast Open compared to TCP New Reno.
// Uses a custom application in order to reset the TCP connection, since all
// performance gains realizable by TCP Fast Open occur during the handshake
// phase.
//
// Adapted from examples/tutorials/fifth.cc
// ===========================================================================
//

bool fastOpen = false;

class ConnectionResettingApplication : public Application
{
public:

  ConnectionResettingApplication ();
  virtual ~ConnectionResettingApplication();

  void Setup (Ptr<Socket> socket, Address address, uint32_t packetSize, uint32_t nPackets, DataRate dataRate, uint32_t resetPercent);
  uint32_t GetPacketsSent (void);
  void ReceivePacket (Ptr<Socket> socket);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void Reconnect (void);
  void ScheduleTx (void);
  void SendPacket (void);

  Ptr<Socket>     m_socket;
  Address         m_peer;
  uint32_t        m_packetSize;
  uint32_t        m_nPackets;
  DataRate        m_dataRate;
  EventId         m_sendEvent;
  bool            m_running;
  uint32_t        m_packetsSent;
  uint32_t        m_resetPercent;
};

ConnectionResettingApplication::ConnectionResettingApplication ()
  : m_socket (0),
    m_peer (),
    m_packetSize (0),
    m_nPackets (0),
    m_dataRate (0),
    m_sendEvent (),
    m_running (false),
    m_packetsSent (0),
    m_resetPercent (0)
{
}

ConnectionResettingApplication::~ConnectionResettingApplication()
{
  m_socket = 0;
}

void
ConnectionResettingApplication::Setup (Ptr<Socket> socket, Address address,
  uint32_t packetSize, uint32_t nPackets, DataRate dataRate, uint32_t resetPercent)
{
  m_socket = socket;
  m_peer = address;
  m_packetSize = packetSize;
  m_nPackets = nPackets;
  m_dataRate = dataRate;
  m_resetPercent = resetPercent;
}

void
ConnectionResettingApplication::StartApplication (void)
{
  m_running = true;
  m_packetsSent = 0;
  m_socket->Bind ();
  m_socket->Connect (m_peer);
  SendPacket ();
}

void
ConnectionResettingApplication::StopApplication (void)
{
  m_running = false;

  if (m_sendEvent.IsRunning ())
    {
      Simulator::Cancel (m_sendEvent);
    }

  if (m_socket)
    {
      m_socket->Close ();
    }
}

void ConnectionResettingApplication::Reconnect (void)
{
  // NS_LOG_UNCOND ("Reconnecting, " << m_packetsSent << " packets sent");
  if (m_socket)
    {
      m_socket->Close ();
    }
  // Queue up a packet to be sent with the SYN-ACK if we're in fast open mode
  if (fastOpen) {
    SendPacket();
  }
  m_socket->Connect (m_peer);
}

void
ConnectionResettingApplication::SendPacket (void)
{
  Ptr<Packet> packet = Create<Packet> (m_packetSize);
  m_socket->Send (packet);
  m_packetsSent++;

  if (m_nPackets == 0 || m_packetsSent < m_nPackets) {
    bool reconnect = m_packetsSent % 100 < m_resetPercent;
    if (reconnect) {
      Reconnect ();
    } else {
      ScheduleTx ();
    }
  }
}

void
ConnectionResettingApplication::ScheduleTx (void)
{
  if (m_running)
    {
      Time tNext (Seconds (m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ())));
      m_sendEvent = Simulator::Schedule (tNext, &ConnectionResettingApplication::SendPacket, this);
    }
}

uint32_t
ConnectionResettingApplication::GetPacketsSent (void) {
  return m_packetsSent;
}

void
ConnectionResettingApplication::ReceivePacket (Ptr<Socket> socket) {
  NS_LOG_UNCOND ("Got a packet");
}

static void
CwndChange (uint32_t oldCwnd, uint32_t newCwnd)
{
  // NS_LOG_UNCOND (Simulator::Now ().GetSeconds () << "\t" << newCwnd);
}

static void
RxDrop (Ptr<const Packet> p)
{
  NS_LOG_UNCOND ("RxDrop at " << Simulator::Now ().GetSeconds ());
  packetsDropped++;

}

int
main (int argc, char *argv[])
{
  uint32_t resetPercent = std::atoi(argv[1]);
  std::string fastOpenFlag = argc >= 3 ? argv[2] : "false";
  fastOpen = (argc >= 2 && fastOpenFlag == "true");
  bool tcp = true;
  double simulationTime = 10; //seconds
  int numPackets = 0;
  Config::SetDefault ("ns3::TcpL4Protocol::SocketType", TypeIdValue (fastOpen ? TcpFastOpen::GetTypeId () : TcpNewReno::GetTypeId()));
  if (argc == 4) {
    std::string logFlag = argv[3];
    if (logFlag == "true") {
      LogComponentEnable ("TcpFastOpen", LOG_LEVEL_ALL);
      LogComponentEnable ("TcpSocketBase", LOG_LEVEL_ALL);
      LogComponentEnable ("TcpHeader", LOG_LEVEL_ALL);
      LogComponentEnable ("TcpOptionFastOpen", LOG_LEVEL_ALL);
    }
  }
  NS_LOG_UNCOND ("Using " << (tcp ? (fastOpen ? "TCP Fast Open" : "TCP New Reno") : "UDP"));

  NodeContainer nodes;
  nodes.Create (2);

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NetDeviceContainer devices;
  devices = pointToPoint.Install (nodes);

  InternetStackHelper stack;
  stack.Install (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.252");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  uint16_t sinkPort = 8080;
  Address sinkAddress (InetSocketAddress (interfaces.GetAddress (1), sinkPort));
  Ptr<Socket> sender;
  PacketSinkHelper packetSinkHelper (tcp ? "ns3::TcpSocketFactory" : "ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
  ApplicationContainer sinkApps = packetSinkHelper.Install (nodes.Get (1));
  sinkApps.Start (Seconds (0.));
  sinkApps.Stop (Seconds (simulationTime + 1));

  if (tcp) {
    sender = Socket::CreateSocket (nodes.Get (0), TcpSocketFactory::GetTypeId ());
    sender->TraceConnectWithoutContext ("CongestionWindow", MakeCallback (&CwndChange));
  } else {
    sender = Socket::CreateSocket (nodes.Get (0), UdpSocketFactory::GetTypeId ());
  }

  AsciiTraceHelper ascii;
  pointToPoint.EnableAsciiAll (ascii.CreateFileStream (fastOpen ? "output/tfo.tr" : "output/baseline.tr"));

  Ptr<ConnectionResettingApplication> app = CreateObject<ConnectionResettingApplication> ();
  app->Setup (sender, sinkAddress, 1040, numPackets, DataRate ("10Mbps"), resetPercent);
  nodes.Get (0)->AddApplication (app);
  app->SetStartTime (Seconds (1.));
  app->SetStopTime (Seconds (simulationTime + 1));

  devices.Get (1)->TraceConnectWithoutContext ("PhyRxDrop", MakeCallback (&RxDrop));

  Simulator::Stop (Seconds (simulationTime + 1));
  Simulator::Run ();

  double throughput = 0.0;
  uint32_t packetsSent = app->GetPacketsSent ();

  throughput = (packetsSent - packetsDropped) * 8 / (simulationTime * 1000.0);

  NS_LOG_UNCOND ("Simulation completed, stats:");
  NS_LOG_UNCOND (packetsSent << " packets sent");
  NS_LOG_UNCOND (packetsDropped << " packets dropped");
  NS_LOG_UNCOND ("Throughput: " << throughput << " Kbits/sec");

  Simulator::Destroy ();

  return 0;
}

