// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

using namespace zeek::packet_analysis::IP;

IPBasedAnalyzer::IPBasedAnalyzer(const char* name)
	: zeek::packet_analysis::Analyzer(name)
	{
	}

IPBasedAnalyzer::~IPBasedAnalyzer()
	{
	}

bool IPBasedAnalyzer::CheckHeaderTrunc(int min_hdr_len, int remaining, Packet* packet)
	{
	uint32_t ip_data_len = packet->ip_hdr->TotalLen() - packet->ip_hdr->HdrLen();

	if ( ip_data_len < min_hdr_len )
		{
		Weird("truncated_header", packet);
		return false;
		}
	else if ( remaining < min_hdr_len )
		{
		Weird("internally_truncated_header", packet);
		return false;
		}

	return true;
	}
