// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/icmp/ICMP.h"
#include "zeek/RunState.h"
#include "zeek/Sessions.h"

using namespace zeek::packet_analysis::ICMP;

ICMPAnalyzer::ICMPAnalyzer()
	: zeek::packet_analysis::IP::IPBasedAnalyzer("ICMP_PKT")
	{
	}

ICMPAnalyzer::~ICMPAnalyzer()
	{
	}

bool ICMPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! CheckHeaderTrunc(ICMP_MINLEN, len, packet) )
		return false;

	sessions->ProcessTransportLayer(run_state::processing_start_time, packet, len);
	return true;
	}
