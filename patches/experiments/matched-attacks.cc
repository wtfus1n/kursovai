// SPDX-License-Identifier: GPL-2.0-only
// prepare_variant.py supplies the protocol and attack definitions.
#if SCALE_AODV
#include "ns3/aodv-module.h"
#else
#include "ns3/olsr-module.h"
#endif
#if SCALE_WORMHOLE
#include "coursework-wormhole-channel.h"
#endif

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/seq-ts-header.h"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

namespace
{
constexpr uint32_t packetSize = 128;
constexpr uint32_t packetCount = 80;
constexpr uint32_t flowCount = 8;
constexpr uint16_t firstDataPort = 9000;
constexpr double packetInterval = 0.25;
constexpr double startTime = 32.0;
constexpr double stopTime = 54.5;
const Ipv4Address fakeBase("10.250.0.1");

#if SCALE_AODV
using RoutingProtocol = aodv::RoutingProtocol;
#else
using RoutingProtocol = olsr::RoutingProtocol;
#endif

/** Counters and fixed traffic inputs for one UDP stream. */
struct Flow
{
    uint32_t source;           ///< Sending node index.
    uint32_t destination;      ///< Receiving node index.
    double start;              ///< First application send time, in seconds.
    uint32_t sent{0};          ///< Planned sends executed.
    uint32_t socketAccepted{0}; ///< Sends accepted by the local socket.
    uint32_t received{0};      ///< Datagrams delivered to the sink.
    uint32_t tunneled{0};      ///< Delivered datagrams that crossed the hidden link.
    double delayMs{0};         ///< Sum of delays of delivered datagrams, in ms.
    uint32_t finalHops{0};     ///< Route distance at the end, zero if absent.
};

/**
 * Send one timestamped UDP datagram.
 * @param flow Destination and traffic counters.
 * @param socket Sending application socket.
 * @param destination IPv4 address of the sink.
 * @param port UDP port of the sink.
 * @param sequence Index within the flow.
 */
void
Send(Flow* flow, Ptr<Socket> socket, Ipv4Address destination, uint16_t port, uint32_t sequence)
{
    SeqTsHeader header;
    header.SetSeq(sequence);
    auto packet = Create<Packet>(packetSize - header.GetSerializedSize());
    packet->AddHeader(header);
    ++flow->sent;
    if (socket->SendTo(packet, 0, InetSocketAddress(destination, port)) >= 0)
    {
        ++flow->socketAccepted;
    }
}

/**
 * Record an application delivery.
 * @param flow Traffic counters.
 * @param packet Received UDP payload.
 * @param source Address of the sender.
 */
void
OnRx(Flow* flow, Ptr<const Packet> packet, const Address& source)
{
    SeqTsHeader header;
    NS_ABORT_MSG_IF(packet->GetSize() < header.GetSerializedSize(), "Missing UDP timestamp");
    packet->PeekHeader(header);
    ++flow->received;
    flow->delayMs += (Simulator::Now() - header.GetTs()).GetSeconds() * 1000.0;
#if SCALE_WORMHOLE
    WormholeDataTag tag;
    flow->tunneled += packet->PeekPacketTag(tag);
#endif
}

#if SCALE_AODV && !SCALE_WORMHOLE && !SCALE_SYBIL
/** @param count Drop counter. @param packet Dropped packet. @param header Its IPv4 header. */
void
OnAodvDrop(uint64_t* count, Ptr<const Packet> packet, const Ipv4Header& header)
{
    ++*count;
}

/** @param count Reply counter. @param destination Claimed destination. @param sequence Advertised sequence. */
void
OnForgedReply(uint64_t* count, Ipv4Address destination, uint32_t sequence)
{
    ++*count;
}
#endif

#if SCALE_AODV && SCALE_SYBIL
/** @param count Announcement counter. @param address Advertised IPv4 identity. */
void
OnFakeHello(uint64_t* count, Ipv4Address address)
{
    ++*count;
}
#endif

/** Values observed for a destination in a native routing table. */
struct Route
{
    Ipv4Address nextHop; ///< Next gateway selected by the protocol.
    uint32_t hops;       ///< Declared distance.
};

/**
 * Read active destinations and gateways from the native protocol.
 * @param protocol Routing instance on the observed node.
 * @return Routing entries indexed by their destination.
 */
std::map<Ipv4Address, Route>
GetRoutes(Ptr<RoutingProtocol> protocol)
{
    std::map<Ipv4Address, Route> routes;
#if SCALE_AODV
    std::ostringstream table;
    protocol->PrintRoutingTable(Create<OutputStreamWrapper>(&table));
    std::istringstream lines(table.str());
    std::string line;
    while (std::getline(lines, line))
    {
        std::istringstream fields(line);
        std::string destination, gateway, interface, state, expiry;
        uint32_t hops;
        if (fields >> destination >> gateway >> interface >> state >> expiry >> hops && state == "UP")
        {
            routes.emplace(Ipv4Address(destination.c_str()), Route{Ipv4Address(gateway.c_str()), hops});
        }
    }
#else
    for (const auto& route : protocol->GetRoutingTableEntries())
    {
        routes.emplace(route.destAddr, Route{route.nextAddr, route.distance});
    }
#endif
    return routes;
}
} // namespace

int
main(int argc, char* argv[])
{
    const std::string attack = SCALE_ATTACK;
    const std::string protocol = SCALE_AODV ? "aodv" : "olsr";
    uint32_t nodeCount = 100;
    std::string topology = "grid";
    uint32_t run = 1;
    uint32_t seed = 49;
    uint32_t identities = 3;
    bool redundant = false;
    bool controlPlaneAttack = false;
    uint32_t tunnelDelayMs = 1;
    double probability = attack == "blackhole" ? 1.0 : 0.5;
    std::string mode = "off";
    CommandLine cmd(__FILE__);
    cmd.AddValue("nodes", "Total nodes (25 to 256)", nodeCount);
    cmd.AddValue("topology", "grid, triangle (3 groups) or ring (4 groups)", topology);
    cmd.AddValue("mode", "off, attack (non-wormhole), control-only or control-and-data (wormhole)", mode);
    cmd.AddValue("seed", "Common ns-3 random seed", seed);
    cmd.AddValue("run", "Common ns-3 repeat number", run);
    if (attack == "grayhole")
    {
        cmd.AddValue("probability", "Grayhole drop probability", probability);
    }
    cmd.AddValue("identities", "Number of false Sybil identities", identities);
    cmd.AddValue("redundant", "Add a second ordinary intergroup link", redundant);
    cmd.AddValue("tunnelDelayMs", "One-way wormhole delay in milliseconds", tunnelDelayMs);
    cmd.AddValue("controlPlaneAttack", "Enable protocol-specific manipulation in drop attacks",
                 controlPlaneAttack);
    cmd.Parse(argc, argv);

    NS_ABORT_MSG_IF(nodeCount < 25 || nodeCount > 256, "Use 25 to 256 nodes");
    NS_ABORT_MSG_IF(topology != "grid" && topology != "triangle" && topology != "ring",
                    "Expected grid, triangle or ring");
    NS_ABORT_MSG_IF(redundant && topology != "grid", "Only grid supports --redundant");
    NS_ABORT_MSG_IF(!(probability >= 0 && probability <= 1), "Invalid drop probability");
    NS_ABORT_MSG_IF(identities == 0 || identities > 64, "Use 1 to 64 Sybil addresses");
#if SCALE_WORMHOLE
    NS_ABORT_MSG_IF(mode != "off" && mode != "control-only" && mode != "control-and-data",
                    "Expected off, control-only or control-and-data");
#else
    NS_ABORT_MSG_IF(mode != "off" && mode != "attack", "Expected off or attack");
#endif
    NS_ABORT_MSG_IF(controlPlaneAttack && (SCALE_WORMHOLE || SCALE_SYBIL),
                    "controlPlaneAttack applies to Blackhole and Grayhole");
#if !SCALE_WORMHOLE
    const bool enabled = mode != "off";
#endif
    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(run);
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));

    const bool grid = topology == "grid";
    const uint32_t groupCount = grid ? 2 : topology == "triangle" ? 3 : 4;
    const uint32_t columns = nodeCount < 50 ? 5 : 10;
    const uint32_t split = columns / 2;
    const uint32_t fullRows = nodeCount / columns;
    std::vector<uint32_t> boundaries{0};
    for (uint32_t group = 1; group <= groupCount; ++group)
    {
        boundaries.push_back(group * nodeCount / groupCount);
    }
    const auto groupOf = [&](uint32_t index) -> uint32_t {
        if (grid)
        {
            return index % columns >= split;
        }
        return std::upper_bound(boundaries.begin(), boundaries.end(), index) - boundaries.begin() - 1;
    };
    const uint32_t bridgeLeft = grid ? split - 1 : boundaries[1] - 1;
    const uint32_t bridgeRight = bridgeLeft + 1;
    const uint32_t backupLeft = (fullRows - 1) * columns + split - 1;
    const uint32_t tunnelLeft = grid ? (fullRows / 2) * columns + split - 1 : boundaries[1] / 2;
    const uint32_t tunnelRight = grid ? tunnelLeft + 1
                                      : boundaries[1] + (boundaries[2] - boundaries[1]) / 2;
    const uint32_t attackerIndex = SCALE_WORMHOLE ? tunnelLeft : bridgeLeft;
    const auto linked = [&](uint32_t a, uint32_t b) {
        const uint32_t i = std::min(a, b);
        const uint32_t j = std::max(a, b);
        if (!grid)
        {
            const uint32_t group = groupOf(i);
            const bool groupLoop = i == boundaries[group] && j == boundaries[group + 1] - 1;
            return i + 1 == j || groupLoop || (i == 0 && j == nodeCount - 1);
        }
        if (groupOf(i) != groupOf(j))
        {
            return (i == bridgeLeft && j == bridgeRight) ||
                   (redundant && i == backupLeft && j == backupLeft + 1);
        }
        return (i / columns == j / columns && i + 1 == j) || i + columns == j;
    };

    NodeContainer nodes;
    nodes.Create(nodeCount);
#if SCALE_WORMHOLE
    auto channel = CreateObject<ComparisonWormholeChannel>();
#else
    auto channel = CreateObject<SimpleChannel>();
#endif
    channel->SetAttribute("Delay", TimeValue(MicroSeconds(100)));
    SimpleNetDeviceHelper network;
    const auto devices = network.Install(nodes, channel);
    for (uint32_t i = 0; i < nodeCount; ++i)
    {
        for (uint32_t j = 0; j < nodeCount; ++j)
        {
            if (i != j && !linked(i, j))
            {
                channel->BlackList(DynamicCast<SimpleNetDevice>(devices.Get(i)),
                                   DynamicCast<SimpleNetDevice>(devices.Get(j)));
            }
        }
    }

#if SCALE_WORMHOLE
    const auto neighborhood = [&](uint32_t endpoint) {
        std::vector<Ptr<SimpleNetDevice>> result;
        for (uint32_t i = 0; i < nodeCount; ++i)
        {
            if (i == endpoint || linked(endpoint, i))
            {
                result.push_back(DynamicCast<SimpleNetDevice>(devices.Get(i)));
            }
        }
        return result;
    };
    using TunnelMode = ComparisonWormholeChannel::Mode;
    auto tunnelMode = TunnelMode::OFF;
    if (mode == "control-only")
    {
        tunnelMode = TunnelMode::CONTROL_ONLY;
    }
    else if (mode == "control-and-data")
    {
        tunnelMode = TunnelMode::CONTROL_AND_DATA;
    }
    channel->Configure(neighborhood(tunnelLeft),
                       neighborhood(tunnelRight),
                       tunnelMode,
                       MilliSeconds(tunnelDelayMs),
                       SCALE_AODV ? 654 : 698);
#endif

    InternetStackHelper stack;
#if SCALE_AODV
    AodvHelper routing;
    routing.Set("EnableHello", BooleanValue(true));
    routing.Set("HelloInterval", TimeValue(Seconds(1)));
    routing.Set("DestinationOnly", BooleanValue(true));
    routing.Set("TtlStart", UintegerValue(10));
#else
    OlsrHelper routing;
    routing.Set("HelloInterval", TimeValue(Seconds(1)));
    routing.Set("TcInterval", TimeValue(Seconds(2)));
#endif
    stack.SetRoutingHelper(routing);
    stack.Install(nodes);
    Ipv4AddressHelper addresses;
    addresses.SetBase("10.1.0.0", "255.255.0.0");
    const auto interfaces = addresses.Assign(devices);
    std::vector<Ptr<RoutingProtocol>> protocols;
    for (uint32_t i = 0; i < nodeCount; ++i)
    {
#if SCALE_AODV
        protocols.push_back(nodes.Get(i)->GetObject<RoutingProtocol>());
#else
        protocols.push_back(
            nodes.Get(i)->GetObject<Ipv4>()->GetRoutingProtocol()->GetObject<RoutingProtocol>());
#endif
    }

    uint64_t dataDrops = 0, controlDrops = 0, forgedReplies = 0, emitted = 0;
#if !SCALE_WORMHOLE
    auto attacker = protocols.at(attackerIndex);
#endif
#if SCALE_SYBIL
    attacker->SetAttribute("SybilEnabled", BooleanValue(enabled));
    attacker->SetAttribute("SybilManualSchedule", BooleanValue(true));
#if SCALE_AODV
    attacker->SetAttribute("SybilIdentityCount", UintegerValue(identities));
    attacker->SetAttribute("SybilFirstAddress", Ipv4AddressValue(fakeBase));
    attacker->TraceConnectWithoutContext("SybilIdentityTx", MakeBoundCallback(&OnFakeHello, &emitted));
#else
    attacker->SetAttribute("SybilCount", UintegerValue(identities));
    attacker->SetAttribute("SybilAddressBase", Ipv4AddressValue(fakeBase));
#endif
    if (enabled)
    {
        for (double time = 1.5; time < stopTime; time += 1.0)
        {
            Simulator::Schedule(Seconds(time), &RoutingProtocol::SendSybilIdentities, attacker);
        }
    }
#elif !SCALE_WORMHOLE
    attacker->SetAttribute("AttackForwardingOnly", BooleanValue(!controlPlaneAttack));
#if SCALE_AODV
    attacker->SetAttribute("IsMalicious", BooleanValue(enabled));
    attacker->TraceConnectWithoutContext("AttackDrop", MakeBoundCallback(&OnAodvDrop, &dataDrops));
    attacker->TraceConnectWithoutContext("ForgedReply", MakeBoundCallback(&OnForgedReply, &forgedReplies));
#else
    attacker->SetAttribute("AttackEnabled", BooleanValue(enabled));
    attacker->SetAttribute("AttackStart", TimeValue(Seconds(0)));
#endif
    if (attack == "grayhole")
    {
        attacker->SetAttribute("AttackDropProbability", DoubleValue(probability));
    }
#endif
    for (uint32_t i = 0; i < nodeCount; ++i)
    {
        protocols[i]->AssignStreams(100 + 8 * i);
    }

    auto rng = CreateObject<UniformRandomVariable>();
    rng->SetStream(90);
    std::vector<std::vector<uint32_t>> groups(groupCount);
    for (uint32_t i = 0; i < nodeCount; ++i)
    {
        if (i != bridgeLeft && i != bridgeRight && i != tunnelLeft && i != tunnelRight)
        {
            groups[groupOf(i)].push_back(i);
        }
    }
    std::vector<Flow> flows;
    flows.reserve(flowCount);
    for (uint32_t i = 0; i < flowCount; ++i)
    {
        const uint32_t sourceGroup = i % groupCount;
        const uint32_t destinationGroup = i < flowCount / 2 ? (sourceGroup + 1) % groupCount
                                                            : sourceGroup;
        const auto& sources = groups[sourceGroup];
        const auto& destinations = groups[destinationGroup];
        const auto source = sources[rng->GetInteger(0, sources.size() - 1)];
        auto destinationIndex = rng->GetInteger(0, destinations.size() - 1);
        if (destinations[destinationIndex] == source)
        {
            destinationIndex = (destinationIndex + 1) % destinations.size();
        }
        flows.push_back({source, destinations[destinationIndex], startTime + rng->GetValue(0.0, 1.5)});
        auto& flow = flows.back();
        const auto port = static_cast<uint16_t>(firstDataPort + i);
        PacketSinkHelper sink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
        auto sinks = sink.Install(nodes.Get(flow.destination));
        sinks.Start(Seconds(0));
        sinks.Get(0)->TraceConnectWithoutContext("Rx", MakeBoundCallback(&OnRx, &flow));
        auto socket = Socket::CreateSocket(nodes.Get(source), UdpSocketFactory::GetTypeId());
        NS_ABORT_MSG_IF(socket->Bind() < 0, "Cannot bind the UDP source");
        for (uint32_t seq = 0; seq < packetCount; ++seq)
        {
            Simulator::Schedule(Seconds(flow.start + seq * packetInterval),
                                &Send,
                                &flow,
                                socket,
                                interfaces.GetAddress(flow.destination),
                                port,
                                seq);
        }
    }
    Simulator::Stop(Seconds(stopTime));
    Simulator::Run();

#if !SCALE_AODV && SCALE_SYBIL
    emitted = attacker->GetSybilPackets();
#elif !SCALE_AODV && !SCALE_WORMHOLE
    dataDrops = attacker->GetAttackDataDrops();
    controlDrops = attacker->GetAttackControlDrops();
#endif

    uint32_t falseGateways = 0;
    uint32_t fakeRoutes = 0;
#if SCALE_WORMHOLE
    const uint32_t first = interfaces.GetAddress(0).Get();
#endif
    for (uint32_t i = 0; i < nodeCount; ++i)
    {
        const auto routes = GetRoutes(protocols[i]);
        for (auto& flow : flows)
        {
            if (flow.source == i)
            {
                const auto found = routes.find(interfaces.GetAddress(flow.destination));
                if (found != routes.end())
                {
                    flow.finalHops = found->second.hops;
                }
            }
        }

#if SCALE_WORMHOLE || SCALE_SYBIL
        if (i == attackerIndex || (SCALE_WORMHOLE && i == tunnelRight))
        {
            continue;
        }
#if SCALE_WORMHOLE
        std::set<uint32_t> unreachableGateways;
        for (const auto& entry : routes)
        {
            const uint32_t gateway = entry.second.nextHop.Get();
            if (gateway >= first && gateway - first < nodeCount && gateway - first != i &&
                !linked(i, gateway - first))
            {
                unreachableGateways.insert(gateway);
            }
        }
        falseGateways += unreachableGateways.size();
#else
        for (const auto& entry : routes)
        {
            const uint32_t destination = entry.first.Get();
            fakeRoutes += destination >= fakeBase.Get() && destination - fakeBase.Get() < identities;
        }
#endif
#endif
    }

    std::cout << std::setprecision(10) << "RESULT {\"protocol\":\"" << protocol
              << "\",\"attack\":\"" << attack << "\",\"mode\":\"" << mode << "\",\"nodes\":" << nodeCount
              << ",\"topology\":\"" << topology << "\",\"groups\":" << groupCount
              << ",\"seed\":" << seed << ",\"run\":" << run << ",\"redundant\":" << redundant
              << ",\"probability\":" << probability << ",\"identities\":" << identities
              << ",\"control_plane_attack\":" << controlPlaneAttack << ",\"tunnel_delay_ms\":" << tunnelDelayMs
              << ",\"attacker\":" << attackerIndex << ",\"peer\":"
              << (SCALE_WORMHOLE ? std::to_string(tunnelRight) : "null")
              << ",\"data_drops\":" << dataDrops << ",\"control_drops\":" << controlDrops
              << ",\"forged_replies\":" << forgedReplies << ",\"sybil_announcements\":" << emitted
              << ",\"fake_routes\":" << fakeRoutes << ",\"false_gateways\":" << falseGateways;
#if SCALE_WORMHOLE
    const auto& counters = channel->GetCounters();
    std::cout << ",\"tunnel_routing_frames\":" << counters.routing << ",\"tunnel_arp_frames\":" << counters.arp
              << ",\"tunnel_data_frames\":" << counters.data << ",\"tunnel_replays\":" << counters.replays;
#endif
    std::cout << ",\"flows\":[";
    for (uint32_t i = 0; i < flows.size(); ++i)
    {
        const auto& flow = flows[i];
        std::cout << (i == 0 ? "" : ",") << "{\"source\":" << flow.source
                  << ",\"destination\":" << flow.destination << ",\"start_s\":" << flow.start
                  << ",\"cross\":" << (groupOf(flow.source) != groupOf(flow.destination) ? "true" : "false")
                  << ",\"sent\":" << flow.sent << ",\"socket_accepted\":" << flow.socketAccepted
                  << ",\"received\":" << flow.received << ",\"tunneled_received\":" << flow.tunneled
                  << ",\"delay_sum_ms\":" << flow.delayMs << ",\"final_hops\":" << flow.finalHops << "}";
    }
    std::cout << "]}" << std::endl;
    Simulator::Destroy();
}

