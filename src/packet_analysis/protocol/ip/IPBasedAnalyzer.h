// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"

namespace zeek::packet_analysis::IP {

/**
 * A base class for any packet analyzer based on IP. This is used by default by
 * the TCP, UDP, and ICMP analyzers to reduce a large amount of duplicated code
 * that those plugins have in common.
 */
class IPBasedAnalyzer : public Analyzer {
public:
	~IPBasedAnalyzer() override;

protected:

	IPBasedAnalyzer(const char* name);

	/**
	 * Verifies that there is enough data in the packet to process the header
	 * length requested.
	 *
	 * @param min_hdr_len The minimum data in bytes that needs to exist.
	 * @param remaining The remaining number of bytes reported by previous analyzer.
	 * @param packet The packet being processed. This will be used to pull out the
	 * number of bytes the IP header says we have remaining.
	 */
	bool CheckHeaderTrunc(int min_hdr_len, int remaining, Packet* packet);

};

}
