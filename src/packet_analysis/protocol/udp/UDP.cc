// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/udp/UDP.h"
#include "zeek/RunState.h"
#include "zeek/Sessions.h"

using namespace zeek::packet_analysis::UDP;

UDPAnalyzer::UDPAnalyzer()
	: zeek::packet_analysis::IP::IPBasedAnalyzer("UDP_PKT")
	{
	}

UDPAnalyzer::~UDPAnalyzer()
	{
	}

bool UDPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	uint32_t min_hdr_len = sizeof(struct udphdr);
	if ( ! CheckHeaderTrunc(min_hdr_len, len, packet) )
		return false;

	sessions->ProcessTransportLayer(run_state::processing_start_time, packet, len);
	return true;
	}
