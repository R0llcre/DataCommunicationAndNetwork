package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.l3routing.IL3Routing;
import edu.wisc.cs.sdn.apps.util.ArpServer;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	private static final byte TCP_FLAG_RST = 0x04;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to L3Routing application
    private IL3Routing l3RoutingApp;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.l3RoutingApp = context.getServiceImpl(IL3Routing.class);
        
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
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
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
			/* TODO: Install rules to send:                                      */
			/*       (1) packets from new connections to each virtual load       */
			/*       balancer IP to the controller                               */
			/*       (2) ARP packets to the controller, and                      */
			/*       (3) all other packets to the next rule table in the switch  */
			// (2) ARP packets to controller
			OFMatch arpMatch = new OFMatch();
			arpMatch.setDataLayerType(Ethernet.TYPE_ARP);
			List<OFAction> arpActions = new ArrayList<OFAction>();
			arpActions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()));
			OFInstructionApplyActions arpApply = new OFInstructionApplyActions();
			arpApply.setActions(arpActions);
			int arpActLen = 0;
			for (OFAction a : arpActions)
			{ arpActLen += a.getLengthU(); }
			arpApply.setLength((short)(OFInstructionApplyActions.MINIMUM_LENGTH
					+ arpActLen));
			List<OFInstruction> arpInstr = new ArrayList<OFInstruction>();
			arpInstr.add(arpApply);
			SwitchCommands.installRule(sw, this.table,
					SwitchCommands.DEFAULT_PRIORITY, arpMatch, arpInstr);
			
			// (1) TCP packets to VIPs to controller
			for (LoadBalancerInstance inst : this.instances.values())
			{
				OFMatch vipMatch = new OFMatch();
				vipMatch.setDataLayerType(Ethernet.TYPE_IPv4);
				vipMatch.setNetworkProtocol(IPv4.PROTOCOL_TCP);
				vipMatch.setNetworkDestination(inst.getVirtualIP());
				
				List<OFAction> vipActions = new ArrayList<OFAction>();
				vipActions.add(new OFActionOutput(
						OFPort.OFPP_CONTROLLER.getValue()));
				OFInstructionApplyActions vipApply =
						new OFInstructionApplyActions();
				vipApply.setActions(vipActions);
				int vipActLen = 0;
				for (OFAction a : vipActions)
				{ vipActLen += a.getLengthU(); }
				vipApply.setLength((short)(
						OFInstructionApplyActions.MINIMUM_LENGTH + vipActLen));
				List<OFInstruction> vipInstr = new ArrayList<OFInstruction>();
				vipInstr.add(vipApply);
				
				SwitchCommands.installRule(sw, this.table,
						SwitchCommands.DEFAULT_PRIORITY, vipMatch, vipInstr);
			}
			
			// (3) Default rule: goto L3Routing table
			OFMatch defaultMatch = new OFMatch();
			OFInstructionGotoTable gotoTable = new OFInstructionGotoTable();
			gotoTable.setTableId(this.l3RoutingApp.getTable());
			gotoTable.setLength((short)OFInstructionGotoTable.MINIMUM_LENGTH);
			List<OFInstruction> defaultInstr = new ArrayList<OFInstruction>();
			defaultInstr.add(gotoTable);
			SwitchCommands.installRule(sw, this.table,
					SwitchCommands.MIN_PRIORITY, defaultMatch, defaultInstr);
			/*********************************************************************/
		}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
			ethPkt.deserialize(pktIn.getPacketData(), 0,
					pktIn.getPacketData().length);
			
			/*********************************************************************/
			/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
			/*       SYNs sent to a virtual IP, select a host and install        */
			/*       connection-specific rules to rewrite IP and MAC addresses;  */
			/*       for all other TCP packets sent to a virtual IP, send a TCP  */
			/*       reset; ignore all other packets                             */
			// Handle ARP requests for virtual IPs
			if (ethPkt.getEtherType() == Ethernet.TYPE_ARP)
			{
				ARP arp = (ARP)ethPkt.getPayload();
				if (arp.getOpCode() == ARP.OP_REQUEST
						&& arp.getProtocolType() == ARP.PROTO_TYPE_IP)
				{
					int targetIP = IPv4.toIPv4Address(
							arp.getTargetProtocolAddress());
					LoadBalancerInstance inst =
							this.instances.get(targetIP);
					if (inst != null)
					{
						log.info(String.format(
								"Received ARP request for VIP %s from %s",
								IPv4.fromIPv4Address(targetIP),
								MACAddress.valueOf(
										arp.getSenderHardwareAddress())
										.toString()));
						
						byte[] vmac = inst.getVirtualMAC();
						arp.setOpCode(ARP.OP_REPLY);
						arp.setTargetHardwareAddress(
								arp.getSenderHardwareAddress());
						arp.setTargetProtocolAddress(
								arp.getSenderProtocolAddress());
						arp.setSenderHardwareAddress(vmac);
						arp.setSenderProtocolAddress(
								IPv4.toIPv4AddressBytes(targetIP));
						ethPkt.setDestinationMACAddress(
								ethPkt.getSourceMACAddress());
						ethPkt.setSourceMACAddress(vmac);
						
						SwitchCommands.sendPacket(sw,
								(short)pktIn.getInPort(), ethPkt);
						return Command.STOP;
					}
				}
				return Command.CONTINUE;
			}
			
			// Handle TCP packets destined to VIPs
			if (ethPkt.getEtherType() == Ethernet.TYPE_IPv4)
			{
				IPv4 ipPkt = (IPv4)ethPkt.getPayload();
				if (ipPkt.getProtocol() == IPv4.PROTOCOL_TCP)
				{
					TCP tcpPkt = (TCP)ipPkt.getPayload();
					int vip = ipPkt.getDestinationAddress();
					LoadBalancerInstance inst = this.instances.get(vip);
					if (inst == null)
					{ return Command.CONTINUE; }
					
					int clientIP = ipPkt.getSourceAddress();
					short clientPort = tcpPkt.getSourcePort();
					short servicePort = tcpPkt.getDestinationPort();
					
					boolean isSyn = (tcpPkt.getFlags() & TCP_FLAG_SYN) != 0;
					if (isSyn)
					{
						int hostIP = inst.getNextHostIP();
						byte[] hostMAC = getHostMACAddress(hostIP);
						if (hostMAC == null)
						{
							log.warn(String.format(
									"Unknown MAC for host %s",
									IPv4.fromIPv4Address(hostIP)));
							return Command.CONTINUE;
						}
						
						byte[] vmac = inst.getVirtualMAC();
						
						// Client -> server rule
						OFMatch c2sMatch = new OFMatch();
						c2sMatch.setDataLayerType(Ethernet.TYPE_IPv4);
						c2sMatch.setNetworkProtocol(IPv4.PROTOCOL_TCP);
						c2sMatch.setNetworkSource(clientIP);
						c2sMatch.setNetworkDestination(vip);
						c2sMatch.setTransportSource(clientPort);
						c2sMatch.setTransportDestination(servicePort);
						
						List<OFAction> c2sActions = new ArrayList<OFAction>();
						c2sActions.add(
								new OFActionSetField(OFOXMFieldType.ETH_DST, hostMAC));
						c2sActions.add(
								new OFActionSetField(OFOXMFieldType.IPV4_DST, hostIP));
						OFInstructionApplyActions c2sApply =
								new OFInstructionApplyActions();
						c2sApply.setActions(c2sActions);
						int c2sActLen = 0;
						for (OFAction a : c2sActions)
						{ c2sActLen += a.getLengthU(); }
						c2sApply.setLength((short)(
								OFInstructionApplyActions.MINIMUM_LENGTH
								+ c2sActLen));
						OFInstructionGotoTable c2sGoto =
								new OFInstructionGotoTable();
						c2sGoto.setTableId(this.l3RoutingApp.getTable());
						c2sGoto.setLength(
								(short)OFInstructionGotoTable.MINIMUM_LENGTH);
						List<OFInstruction> c2sInstr =
								new ArrayList<OFInstruction>();
						c2sInstr.add(c2sApply);
						c2sInstr.add(c2sGoto);
						
						SwitchCommands.installRule(sw, this.table,
								SwitchCommands.MAX_PRIORITY, c2sMatch,
								c2sInstr, SwitchCommands.NO_TIMEOUT,
								IDLE_TIMEOUT, pktIn.getBufferId());
						
						// Server -> client rule
						OFMatch s2cMatch = new OFMatch();
						s2cMatch.setDataLayerType(Ethernet.TYPE_IPv4);
						s2cMatch.setNetworkProtocol(IPv4.PROTOCOL_TCP);
						s2cMatch.setNetworkSource(hostIP);
						s2cMatch.setNetworkDestination(clientIP);
						s2cMatch.setTransportSource(servicePort);
						s2cMatch.setTransportDestination(clientPort);
						
						List<OFAction> s2cActions = new ArrayList<OFAction>();
						s2cActions.add(
								new OFActionSetField(OFOXMFieldType.ETH_SRC, vmac));
						s2cActions.add(
								new OFActionSetField(OFOXMFieldType.IPV4_SRC, vip));
						OFInstructionApplyActions s2cApply =
								new OFInstructionApplyActions();
						s2cApply.setActions(s2cActions);
						int s2cActLen = 0;
						for (OFAction a : s2cActions)
						{ s2cActLen += a.getLengthU(); }
						s2cApply.setLength((short)(
								OFInstructionApplyActions.MINIMUM_LENGTH
								+ s2cActLen));
						OFInstructionGotoTable s2cGoto =
								new OFInstructionGotoTable();
						s2cGoto.setTableId(this.l3RoutingApp.getTable());
						s2cGoto.setLength(
								(short)OFInstructionGotoTable.MINIMUM_LENGTH);
						List<OFInstruction> s2cInstr =
								new ArrayList<OFInstruction>();
						s2cInstr.add(s2cApply);
						s2cInstr.add(s2cGoto);
						
						SwitchCommands.installRule(sw, this.table,
								SwitchCommands.MAX_PRIORITY, s2cMatch,
								s2cInstr, SwitchCommands.NO_TIMEOUT,
								IDLE_TIMEOUT);
						
						return Command.STOP;
					}
					else
					{
						// Send TCP RST from VIP to client
						Ethernet rstEth = new Ethernet();
						rstEth.setSourceMACAddress(inst.getVirtualMAC());
						rstEth.setDestinationMACAddress(
								ethPkt.getSourceMACAddress());
						rstEth.setEtherType(Ethernet.TYPE_IPv4);
						
						IPv4 rstIp = new IPv4();
						rstIp.setSourceAddress(vip);
						rstIp.setDestinationAddress(clientIP);
						rstIp.setProtocol(IPv4.PROTOCOL_TCP);
						rstIp.setTtl((byte)64);
						
						TCP rstTcp = new TCP();
						rstTcp.setSourcePort(servicePort);
						rstTcp.setDestinationPort(clientPort);
						// Best-effort RST: mirror ack/seq so host accepts reset
						rstTcp.setSequence(tcpPkt.getAcknowledge());
						rstTcp.setAcknowledge(tcpPkt.getSequence() + 1);
						rstTcp.setFlags((short)(TCP_FLAG_RST | 0x10));
						rstTcp.setPayload(new Data(new byte[0]));
						
						rstIp.setPayload(rstTcp);
						rstEth.setPayload(rstIp);
						
						SwitchCommands.sendPacket(sw,
								(short)pktIn.getInPort(), rstEth);
						return Command.STOP;
					}
				}
			}
			/*********************************************************************/
			
			return Command.CONTINUE;
	}
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

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
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
