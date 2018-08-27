##! Cluster transparency support for the intelligence framework.  This is mostly
##! oriented toward distributing intelligence information across clusters.

@load ./main
@load base/frameworks/cluster

module Intel;

export {
	## Broker topic for management of intel items. Sending insert_item and
	## remove_item events, peers can manage intelligence data.
	const item_topic = "bro/intel/items" &redef;

	## Broker topic for management of intel indicators as stored on workers
	## for matching. Sending insert_indicator and remove_indicator events,
	## the back-end manages indicators.
	const indicator_topic = "bro/intel/indicators" &redef;

	## Broker topic for matching events, generated by workers and sent to
	## the back-end for metadata enrichment and logging.
	const match_topic = "bro/intel/match" &redef;
}

# Internal events for cluster data distribution.
global insert_item: event(item: Item);
global insert_indicator: event(item: Item);

# If this process is not a manager process, we don't want the full metadata.
@if ( Cluster::local_node_type() != Cluster::MANAGER )
redef have_full_data = F;
@endif

@if ( Cluster::local_node_type() == Cluster::MANAGER )
event bro_init()
	{
	Broker::subscribe(item_topic);
	Broker::subscribe(match_topic);

	Broker::auto_publish(indicator_topic, remove_indicator);
	}

# Handling of new worker nodes.
event Cluster::node_up(name: string, id: string)
	{
	# When a worker connects, send it the complete minimal data store.
	# It will be kept up to date after this by the insert_indicator event.
	if ( name in Cluster::nodes && Cluster::nodes[name]$node_type == Cluster::WORKER )
		{
		Broker::publish_id(Cluster::node_topic(name), "Intel::min_data_store");
		}
	}

# On the manager, the new_item event indicates a new indicator that
# has to be distributed.
event Intel::new_item(item: Item) &priority=5
	{
	local pt = Cluster::rr_topic(Cluster::proxy_pool, indicator_topic);

	if ( pt == "" )
		# No proxies alive, publish to all workers ourself instead of
		# relaying via a proxy.
		pt = indicator_topic;

	Broker::publish(pt, Intel::insert_indicator, item);
	}

# Handling of item insertion triggered by remote node.
event Intel::insert_item(item: Intel::Item) &priority=5
	{
	Intel::_insert(item, T);
	}

# Handling of item removal triggered by remote node.
event Intel::remove_item(item: Item, purge_indicator: bool) &priority=5
	{
	remove(item, purge_indicator);
	}

# Handling of match triggered by remote node.
event Intel::match_remote(s: Seen) &priority=5
	{
	if ( Intel::find(s) )
		event Intel::match(s, Intel::get_items(s));
	}
@endif

@if ( Cluster::local_node_type() == Cluster::WORKER )
event bro_init()
	{
	Broker::subscribe(indicator_topic);

	Broker::auto_publish(match_topic, match_remote);
	Broker::auto_publish(item_topic, remove_item);
	}

# On a worker, the new_item event requires to trigger the insertion
# on the manager to update the back-end data store.
event Intel::new_item(item: Intel::Item) &priority=5
	{
	Broker::publish(item_topic, Intel::insert_item, item);
	}

# Handling of new indicators published by the manager.
event Intel::insert_indicator(item: Intel::Item) &priority=5
	{
	Intel::_insert(item, F);
	}
@endif

@if ( Cluster::local_node_type() == Cluster::PROXY )
event Intel::insert_indicator(item: Intel::Item) &priority=5
	{
	# Just forwarding from manager to workers.
	Broker::publish(indicator_topic, Intel::insert_indicator, item);
	}
@endif

