// SPDX-License-Identifier: GPL-2.0-only
// Three-hop UDP path: source (0) -> attacker (1) -> relay (2) -> sink (3).
#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include <cmath>
#include <fstream>
#include <iostream>

using namespace ns3;
static uint32_t drops = 0;
static uint32_t forgeries = 0;
static uint32_t transit = 0;
static uint32_t localRx = 0;
static uint32_t ordinaryIpDrops = 0;
static uint32_t ordinaryDropReason = 0;
static uint64_t dropFingerprint = 1469598103934665603ULL;
static void Dropped(Ptr<const Packet> packet, const Ipv4Header&)
{
    ++drops;
    dropFingerprint = (dropFingerprint ^ packet->GetUid()) * 1099511628211ULL;
}
static void OrdinaryDrop(const Ipv4Header& header, Ptr<const Packet>,
                         Ipv4L3Protocol::DropReason reason, Ptr<Ipv4>, uint32_t)
{
    if (header.GetSource() == Ipv4Address("10.0.0.1") &&
        header.GetDestination() == Ipv4Address("10.0.0.4"))
    {
        ++ordinaryIpDrops;
        ordinaryDropReason = static_cast<uint32_t>(reason);
    }
}
static void Forged(Ipv4Address, uint32_t) { ++forgeries; }
static void Forwarded(const Ipv4Header&, Ptr<const Packet>, uint32_t) { ++transit; }
static void LocalReceived(Ptr<const Packet>, const Address&) { ++localRx; }

static int
CheckAutomaticStreams()
{
    auto start = RngSeedManager::GetNextStreamIndex();
    auto protocol = CreateObject<aodv::RoutingProtocol>();
    auto automaticOff = RngSeedManager::GetNextStreamIndex() - start - 1;
    auto assignedOff = protocol->AssignStreams(200);

    bool grayhole = protocol->SetAttributeFailSafe("AttackDropProbability", DoubleValue(0.5));
    auto automaticAssignedOn = uint64_t{0};
    auto assignedOn = int64_t{0};
    if (grayhole)
    {
        protocol->SetAttribute("IsMalicious", BooleanValue(true));
        start = RngSeedManager::GetNextStreamIndex();
        assignedOn = protocol->AssignStreams(200);
        automaticAssignedOn = RngSeedManager::GetNextStreamIndex() - start - 1;
    }
    std::cout << "{\"automaticStreamsOff\":" << automaticOff << ",\"assignedOff\":" << assignedOff
              << ",\"automaticStreamsWhileAssigningOn\":" << automaticAssignedOn
              << ",\"assignedOn\":" << assignedOn << "}" << std::endl;
    bool ok = automaticOff == 1 && assignedOff == 1 &&
              (!grayhole || (automaticAssignedOn == 0 && assignedOn == 2));
    Simulator::Destroy();
    return ok ? 0 : 1;
}

int main(int argc, char** argv)
{
    bool malicious = false;
    bool checkAutomaticStreams = false;
    bool delayedStart = false;
    double probability = 1.0;
    uint32_t seed = 17;
    uint64_t run = 1;
    uint32_t packets = 300;
    CommandLine cmd(__FILE__);
    cmd.AddValue("malicious", "Enable attacker on node 1", malicious);
    cmd.AddValue("checkAutomaticStreams", "Check RNG allocation without running the traffic scenario", checkAutomaticStreams);
    cmd.AddValue("probability", "Gray-hole drop probability", probability);
    cmd.AddValue("delayedStart", "Start grayhole packet dropping at 6 seconds", delayedStart);
    cmd.AddValue("seed", "RNG seed", seed);
    cmd.AddValue("run", "RNG run number", run);
    cmd.AddValue("packets", "Number of UDP packets", packets);
    cmd.Parse(argc, argv);
    const Time trafficStart = Seconds(2);
    const Time dropStart = Seconds(6);
    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(run);
    if (checkAutomaticStreams)
    {
        return CheckAutomaticStreams();
    }
    NodeContainer nodes;
    nodes.Create(4);
    YansWifiChannelHelper channel;
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::RangePropagationLossModel", "MaxRange", DoubleValue(75));
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211g);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue("ErpOfdmRate6Mbps"),
                                 "ControlMode", StringValue("ErpOfdmRate6Mbps"));
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);
    wifi.AssignStreams(devices, 1000);
    MobilityHelper mobility;
    auto positions = CreateObject<ListPositionAllocator>();
    for (uint32_t i=0; i<4; ++i) positions->Add(Vector(i*60.0, 0, 0));
    mobility.SetPositionAllocator(positions);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);
    AodvHelper aodv;
    aodv.Set("EnableHello", BooleanValue(true));
    // Reach node 3 on the first RREQ; avoid testing expanding-ring delay here.
    aodv.Set("TtlStart", UintegerValue(5));
    InternetStackHelper internet;
    internet.SetRoutingHelper(aodv);
    internet.Install(nodes);
    auto attacker=nodes.Get(1)->GetObject<aodv::RoutingProtocol>();
    attacker->SetAttribute("IsMalicious", BooleanValue(malicious));
    for (uint32_t i=0; i<4; ++i)
    {
        auto routing=nodes.Get(i)->GetObject<aodv::RoutingProtocol>();
        routing->AssignStreams(100 + 10*i);
    }
    const bool hasProbability =
        attacker->SetAttributeFailSafe("AttackDropProbability", DoubleValue(delayedStart ? 0.0 : probability));
    NS_ABORT_MSG_IF(delayedStart &&
                        (!malicious || !hasProbability || packets <= 100 ||
                         !(probability >= 0.0 && probability <= 1.0)),
                    "Delayed start requires the enabled grayhole patch, more than 100 packets, and p in [0, 1]");
    attacker->TraceConnectWithoutContext("AttackDrop", MakeCallback(&Dropped));
    attacker->TraceConnectWithoutContext("ForgedReply", MakeCallback(&Forged));
    nodes.Get(1)->GetObject<Ipv4L3Protocol>()->TraceConnectWithoutContext("UnicastForward", MakeCallback(&Forwarded));
    nodes.Get(1)->GetObject<Ipv4L3Protocol>()->TraceConnectWithoutContext("Drop", MakeCallback(&OrdinaryDrop));
    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.255.255.0");
    auto interfaces = address.Assign(devices);
    PacketSinkHelper sink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 9000));
    auto receiver=sink.Install(nodes.Get(3));
    receiver.Start(Seconds(0));
    auto target=DynamicCast<PacketSink>(receiver.Get(0));
    PacketSinkHelper localSink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 9001));
    auto localReceiver=localSink.Install(nodes.Get(1));
    localReceiver.Start(Seconds(0));
    localReceiver.Get(0)->TraceConnectWithoutContext("Rx", MakeCallback(&LocalReceived));
    UdpClientHelper client(interfaces.GetAddress(3), 9000);
    client.SetAttribute("MaxPackets", UintegerValue(packets));
    client.SetAttribute("Interval", TimeValue(MilliSeconds(40)));
    client.SetAttribute("PacketSize", UintegerValue(128));
    auto sender=client.Install(nodes.Get(0));
    sender.Start(trafficStart);
    UdpClientHelper localClient(interfaces.GetAddress(1), 9001);
    localClient.SetAttribute("MaxPackets", UintegerValue(10));
    localClient.SetAttribute("Interval", TimeValue(MilliSeconds(100)));
    localClient.SetAttribute("PacketSize", UintegerValue(128));
    auto localSender=localClient.Install(nodes.Get(0));
    localSender.Start(Seconds(0.5));
    uint64_t receivedBefore = 0;
    uint32_t transitBefore = 0;
    if (delayedStart)
    {
        Simulator::Schedule(dropStart, [&, attacker, target] {
            receivedBefore = target->GetTotalRx() / 128;
            transitBefore = transit;
            attacker->SetAttribute("AttackDropProbability", DoubleValue(probability));
        });
    }
    Simulator::Stop(Seconds(5 + packets*0.04));
    Simulator::Run();
    auto received=target->GetTotalRx()/128;
    std::cout << "{\"malicious\":" << malicious << ",\"probability\":" << probability
              << ",\"seed\":" << seed << ",\"run\":" << run << ",\"sent\":" << packets
              << ",\"received\":" << received << ",\"attackDrops\":" << drops
              << ",\"forgedReplies\":" << forgeries << ",\"ipForwarded\":" << transit
              << ",\"ordinaryIpDrops\":" << ordinaryIpDrops << ",\"ordinaryDropReason\":" << ordinaryDropReason
              << ",\"localReceived\":" << localRx << ",\"dropFingerprint\":" << dropFingerprint;
    const auto receivedAfter = received - receivedBefore;
    if (delayedStart)
    {
        std::cout << ",\"dropStart\":" << dropStart.GetSeconds()
                  << ",\"receivedBefore\":" << receivedBefore
                  << ",\"receivedAfter\":" << receivedAfter;
    }
    std::cout << "}" << std::endl;
    bool ok = localRx == 10 && (!delayedStart || receivedBefore > 0);
    if (!malicious || probability==0) ok=ok && received>packets*0.9 && drops==0;
    else if (probability==1) ok=ok && receivedAfter==0 && drops>0 && forgeries>0;
    else ok=ok && receivedAfter>0 && drops>0 && forgeries>0 &&
                std::abs(static_cast<double>(drops)/(drops+transit-transitBefore)-probability)<0.15;
    Simulator::Destroy();
    return ok ? 0 : 1;
}
