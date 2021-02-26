// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

namespace zeek::packet_analysis::TCP {

class TCPAnalyzer : public zeek::packet_analysis::IP::IPBasedAnalyzer {
public:
	TCPAnalyzer();
	~TCPAnalyzer() override;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<TCPAnalyzer>();
		}

private:

};

}
