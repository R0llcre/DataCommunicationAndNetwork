package edu.wisc.cs.sdn.apps.l3routing;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.Host;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.util.MACAddress;

public class L3Routing implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener, IL3Routing
{
	public static final String MODULE_NAME = L3Routing.class.getSimpleName();
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		this.recomputeAndInstallAllRoutes();
		/*********************************************************************/
	}
	
	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable()
	{ return this.table; }
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
	    /**
	     * Get a list of all active links in the network.
	     */
	    private Collection<Link> getLinks()
	    { return linkDiscProv.getLinks().keySet(); }

	    /**
	     * Build adjacency map: switch -> (neighbor -> outPort).
	     */
	    private Map<Long, Map<Long, Short>> buildAdjacency(Collection<Link> links)
	    {
	    	Map<Long, Map<Long, Short>> adj = new HashMap<Long, Map<Long, Short>>();
	    	for (Link l : links)
	    	{
	    		long src = l.getSrc();
	    		long dst = l.getDst();
	    		short srcPort = l.getSrcPort();
	    		short dstPort = l.getDstPort();
	    		
	    		if (!adj.containsKey(src))
	    		{ adj.put(src, new HashMap<Long, Short>()); }
	    		if (!adj.containsKey(dst))
	    		{ adj.put(dst, new HashMap<Long, Short>()); }
	    		
	    		adj.get(src).put(dst, srcPort);
	    		adj.get(dst).put(src, dstPort);
	    	}
	    	return adj;
	    }
	    
	    /**
	     * Compute next hop toward dstSw for every reachable switch using BFS.
	     * Returns map sw -> next switch on path to dstSw.
	     */
	    private Map<Long, Long> computeNextHopToDst(long dstSw,
	    		Map<Long, Map<Long, Short>> adj)
	    {
	    	Map<Long, Long> nextHop = new HashMap<Long, Long>();
	    	Set<Long> visited = new HashSet<Long>();
	    	Deque<Long> queue = new ArrayDeque<Long>();
	    	visited.add(dstSw);
	    	queue.add(dstSw);
	    	
	    	while (!queue.isEmpty())
	    	{
	    		long cur = queue.remove();
	    		Map<Long, Short> neighbors = adj.get(cur);
	    		if (neighbors == null)
	    		{ continue; }
	    		for (Long nb : neighbors.keySet())
	    		{
	    			if (visited.contains(nb))
	    			{ continue; }
	    			visited.add(nb);
	    			nextHop.put(nb, cur);
	    			queue.add(nb);
	    		}
	    	}
	    	return nextHop;
	    }
	    
	    /**
	     * Remove all rules installed by this app from its table on all switches.
	     */
	    private void clearRoutingTableOnAllSwitches(Map<Long, IOFSwitch> switches)
	    {
	    	OFMatch matchAll = new OFMatch();
	    	matchAll.setWildcards(OFMatch.OFPFW_ALL);
	    	for (IOFSwitch sw : switches.values())
	    	{ SwitchCommands.removeRules(sw, this.table, matchAll); }
	    }
	    
	    /**
	     * Recompute shortest paths to every host and install forwarding rules.
	     * Simple approach: clear this table and reinstall for all hosts.
	     */
	    private synchronized void recomputeAndInstallAllRoutes()
	    {
	    	Map<Long, IOFSwitch> switches = getSwitches();
	    	Collection<Link> links = getLinks();
	    	Collection<Host> hosts = getHosts();
	    	
	    	clearRoutingTableOnAllSwitches(switches);
	    	
	    	Map<Long, Map<Long, Short>> adj = buildAdjacency(links);
	    	
	    	for (Host dstHost : hosts)
	    	{
	    		if (dstHost.getIPv4Address() == null)
	    		{ continue; }
	    		if (!dstHost.isAttachedToSwitch() || dstHost.getPort() == null)
	    		{ continue; }
	    		
	    		long dstSwId = dstHost.getSwitch().getId();
	    		short hostPort = dstHost.getPort().shortValue();
	    		
	    		Map<Long, Long> nextHop = computeNextHopToDst(dstSwId, adj);
	    		
	    		// Match IPv4 packets destined to this host's MAC
	    		OFMatch match = new OFMatch();
	    		match.setDataLayerType(Ethernet.TYPE_IPv4);
	    		match.setDataLayerDestination(
	    				MACAddress.valueOf(dstHost.getMACAddress()).toBytes());
	    		int wildcards = OFMatch.OFPFW_ALL;
	    		wildcards &= ~OFMatch.OFPFW_DL_TYPE;
	    		wildcards &= ~OFMatch.OFPFW_DL_DST;
	    		match.setWildcards(wildcards);
	    		
	    		for (Map.Entry<Long, IOFSwitch> swEntry : switches.entrySet())
	    		{
	    			long swId = swEntry.getKey();
	    			IOFSwitch sw = swEntry.getValue();
	    			
	    			short outPort;
	    			if (swId == dstSwId)
	    			{ outPort = hostPort; }
	    			else
	    			{
	    				Long nh = nextHop.get(swId);
	    				if (nh == null)
	    				{ continue; }
	    				Map<Long, Short> ports = adj.get(swId);
	    				if (ports == null)
	    				{ continue; }
	    				Short port = ports.get(nh);
	    				if (port == null)
	    				{ continue; }
	    				outPort = port.shortValue();
	    			}
	    			
	    			List<OFAction> actions = new ArrayList<OFAction>();
	    			actions.add(new OFActionOutput(outPort));
	    			OFInstructionApplyActions applyActions =
	    					new OFInstructionApplyActions();
	    			applyActions.setActions(actions);
	    			int actionLen = 0;
	    			for (OFAction a : actions)
	    			{ actionLen += a.getLengthU(); }
	    			applyActions.setLength((short)(
	    					OFInstructionApplyActions.MINIMUM_LENGTH + actionLen));
	    			List<OFInstruction> instructions =
	    					new ArrayList<OFInstruction>();
	    			instructions.add(applyActions);
	    			
	    			SwitchCommands.installRule(sw, this.table,
	    					SwitchCommands.DEFAULT_PRIORITY, match, instructions);
	    		}
	    	}
	    }

	    /**
	     * Event handler called when a host joins the network.
	     * @param device information about the host
	     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
				log.info(String.format("Host %s added", host.getName()));
				this.knownHosts.put(device, host);
				
				/*****************************************************************/
				/* TODO: Update routing: add rules to route to new host          */
				this.recomputeAndInstallAllRoutes();
				/*****************************************************************/
			}
		}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
			log.info(String.format("Host %s is no longer attached to a switch", 
					host.getName()));
			
			/*********************************************************************/
			/* TODO: Update routing: remove rules to route to host               */
			this.knownHosts.remove(device);
			this.recomputeAndInstallAllRoutes();
			/*********************************************************************/
		}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
			log.info(String.format("Host %s moved to s%d:%d", host.getName(),
					host.getSwitch().getId(), host.getPort()));
			
			/*********************************************************************/
			/* TODO: Update routing: change rules to route to host               */
			this.knownHosts.put(device, new Host(device, this.floodlightProv));
			this.recomputeAndInstallAllRoutes();
			/*********************************************************************/
		}
	
    /**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override		
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
			log.info(String.format("Switch s%d added", switchId));
			
			/*********************************************************************/
			/* TODO: Update routing: change routing rules for all hosts          */
			this.recomputeAndInstallAllRoutes();
			/*********************************************************************/
		}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
			log.info(String.format("Switch s%d removed", switchId));
			
			/*********************************************************************/
			/* TODO: Update routing: change routing rules for all hosts          */
			this.recomputeAndInstallAllRoutes();
			/*********************************************************************/
		}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> %s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		
			/*********************************************************************/
			/* TODO: Update routing: change routing rules for all hosts          */
			this.recomputeAndInstallAllRoutes();
			/*********************************************************************/
		}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{
		Collection<Class<? extends IFloodlightService>> services =
					new ArrayList<Class<? extends IFloodlightService>>();
		services.add(IL3Routing.class);
		return services; 
	}

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ 
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
        			new HashMap<Class<? extends IFloodlightService>, 
        					IFloodlightService>();
        // We are the class that implements the service
        services.put(IL3Routing.class, this);
        return services;
	}

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> modules =
	            new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
        return modules;
	}
}
