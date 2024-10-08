// file: Program.cs
// author: Veranika Saltanava <xsalta01>

using PacketDotNet;
using SharpPcap;

namespace ipk_sniffer
{
    /// <summary>
    /// This class is responsible for capturing packets and printing their information.
    /// </summary>
    public class Program
    {
        private static bool _exitRequested;
        private static int _packetCount;
        private static ICaptureDevice? _captureDevice;
        
        /// <summary>
        /// This method is the entry point of the program.
        /// </summary>
        public static void Main()
        {
            Console.CancelKeyPress += Console_CancelKeyPress!;

            UserInterface ui = new UserInterface();
            ui.ParseCommandLineArgs(Environment.GetCommandLineArgs());
            
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No interface found on this machine");
                return;
            }

            if (ui.InterfaceName == null)
            {
                return;
            }
            
            var device = devices.FirstOrDefault(dev => dev.Name == ui.InterfaceName);
            if (device == null)
            {
                Console.WriteLine("Interface not found");
                return;
            }
            _captureDevice = device;
            
            
            //device.OnPacketArrival += device_OnPacketArrival;
            device.OnPacketArrival += (_, e) => device_OnPacketArrival(e, ui);

            // Open the device for capturing
            device.Open(DeviceModes.Promiscuous);

            // Apply filters if specified in command line arguments
            if (!string.IsNullOrEmpty(ui.Filter))
            {
                Console.WriteLine($"Applying filter: {ui.Filter}");
                device.Filter = ui.Filter;
            }      
            
            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, hit 'Enter' to stop...",
                device.Name, device.Description);
            Console.WriteLine();

            while (!_exitRequested)
            {

                // Start the capturing process
                device.StartCapture();

                // Wait for 'Enter' from the user.
                Console.ReadLine();

                // Stop the capturing process
                device.StopCapture();

                Console.WriteLine("-- Capture stopped.");
            }
            Console.WriteLine("Program terminated by Ctrl + C.");
        }
        
        /// <summary>
        /// This method is called when a packet is captured.
        /// It parses the packet and prints its information.
        /// </summary>
        private static void device_OnPacketArrival(PacketCapture e, UserInterface ui)
        {
            var time = e.Header.Timeval.Date;
            var rawPacket = e.GetPacket();

            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            
            // check if the packet is an Ethernet packet
            if (packet is EthernetPacket ethernetPacket)
            {
                var packetInfo = new PacketInfo
                {
                    Timestamp = time,
                    SrcMac = ethernetPacket.SourceHardwareAddress.ToString(),
                    DstMac = ethernetPacket.DestinationHardwareAddress.ToString(),
                    FrameLength = rawPacket.Data.Length,
                    HexDump = ByteArrayToString(rawPacket.Data)
                };
                
                // get the payload packet
                var payloadPacket = ethernetPacket.PayloadPacket;
                
                if (payloadPacket is IPPacket ipPacket)
                {
                    packetInfo.SrcIp = ipPacket.SourceAddress?.ToString();
                    packetInfo.DstIp = ipPacket.DestinationAddress?.ToString();

                    if (ipPacket.PayloadPacket is UdpPacket)
                    {
                        var udpPacket = (UdpPacket)ipPacket.PayloadPacket;
                        packetInfo.SrcPort = udpPacket.SourcePort;
                        packetInfo.DstPort = udpPacket.DestinationPort;
                        packetInfo.Protocol = "UDP";
                    }
                    else if (ipPacket.PayloadPacket is TcpPacket)
                    {
                        var tcpPacket = (TcpPacket)ipPacket.PayloadPacket;
                        packetInfo.SrcPort = tcpPacket.SourcePort;
                        packetInfo.DstPort = tcpPacket.DestinationPort;
                        packetInfo.Protocol = "TCP";
                    }
                    else if (ipPacket.PayloadPacket is IcmpV4Packet)
                    {
                        packetInfo.SrcPort = 0; // ICMP doesn't have port numbers
                        packetInfo.DstPort = 0; // ICMP doesn't have port numbers
                        packetInfo.Protocol = "ICMPv4";
                    }
                    else if (ipPacket.PayloadPacket is IcmpV6Packet icmpV6Packet)
                    {
                        packetInfo.SrcPort = 0; // ICMP doesn't have port numbers
                        packetInfo.DstPort = 0; // ICMP doesn't have port numbers
                        
                        if (icmpV6Packet.Type == IcmpV6Type.Version2MulticastListenerReport || 
                            icmpV6Packet.Type == IcmpV6Type.MulticastListenerDone ||
                            icmpV6Packet.Type == IcmpV6Type.MulticastListenerReport ||
                            icmpV6Packet.Type == IcmpV6Type.MulticastListenerQuery )
                        {
                            packetInfo.Protocol = "MLD";
                        }
                        else if (icmpV6Packet.Type == IcmpV6Type.RouterSolicitation || 
                                 icmpV6Packet.Type == IcmpV6Type.RouterAdvertisement || 
                                 icmpV6Packet.Type == IcmpV6Type.NeighborSolicitation || 
                                 icmpV6Packet.Type == IcmpV6Type.NeighborAdvertisement || 
                                 icmpV6Packet.Type == IcmpV6Type.RedirectMessage)
                        {
                            packetInfo.Protocol = "NDP";
                        }
                        else
                        {
                            packetInfo.Protocol = "ICMPv6";
                        }
                    }
                    else if (ipPacket.PayloadPacket is IgmpPacket)
                    {
                        packetInfo.Protocol = "IGMP";
                    }
                    
                    PrintPacketInfo(packetInfo);
                }
                else if (payloadPacket is ArpPacket arpPacket)
                {
                    var arpInfo = new ArpInfo
                    {
                        Timestamp = time,
                        SenderIp = arpPacket.SenderProtocolAddress?.ToString(),
                        SenderMac = arpPacket.SenderHardwareAddress?.ToString(),
                        TargetIp = arpPacket.TargetProtocolAddress?.ToString(),
                        TargetMac = arpPacket.TargetHardwareAddress?.ToString(),
                        Operation = arpPacket.Operation.ToString(),
                        Protocol = "ARP",
                        HexDump = ByteArrayToString(rawPacket.Data)
                    };
                     PrintArpInfo(arpInfo);
                }
            }
            else  
            { 
                Console.WriteLine("Unknown packet type");
            }
            
            _packetCount++;
            
            // terminate the program if the number of packets is reached
            if (_packetCount >= ui.NumPackets)
            {
                _captureDevice?.StopCapture();
                Console.WriteLine("-- Capture stopped.");
                Environment.Exit(0);
            }
        }

        /// <summary>
        ///  This method prints the information about the packet.
        /// </summary>
        /// <param name="packetInfo"></param>
        private static void PrintPacketInfo(PacketInfo packetInfo)
        {
            Console.WriteLine($"timestamp: {packetInfo.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss:fffzzz")}");
            Console.WriteLine($"src MAC: {packetInfo.SrcMac}");
            Console.WriteLine($"dst MAC: {packetInfo.DstMac}");
            Console.WriteLine($"frame length: {packetInfo.FrameLength} bytes");
            Console.WriteLine($"src IP: {packetInfo.SrcIp}");
            Console.WriteLine($"dst IP: {packetInfo.DstIp}");
            // these five protocols don't have port numbers
            if (packetInfo.Protocol != "ICMPv4" && 
                packetInfo.Protocol != "ICMPv6" && 
                packetInfo.Protocol != "IGMP" &&
                packetInfo.Protocol != "MLD" &&
                packetInfo.Protocol != "NDP")
            {
                Console.WriteLine($"src port: {packetInfo.SrcPort}");
                Console.WriteLine($"dst port: {packetInfo.DstPort}");
            }
            Console.WriteLine($"protocol: {packetInfo.Protocol}");
            Console.WriteLine();
            Console.WriteLine(packetInfo.HexDump);
            Console.WriteLine();
            Console.WriteLine();
        }
     
        /// <summary>
        /// This method converts a byte array to a string.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        private static string ByteArrayToString(byte[] bytes)
        {
            const int bytesPerLine = 16;
            int byteCount = 0;
            var hexDump = new System.Text.StringBuilder();

            foreach (var b in bytes)
            {
                if (byteCount % bytesPerLine == 0)
                {
                    hexDump.Append($"{Environment.NewLine}0x{byteCount:x4}: ");
                }

                hexDump.Append($"{b:x2} ");
                byteCount++;
                
                if (byteCount % bytesPerLine == 0)
                {
                    hexDump.Append(' ');
                    var asciiString =System.Text.Encoding.ASCII.GetString(bytes, byteCount - bytesPerLine, bytesPerLine);
                    for (int i = 0; i < asciiString.Length; i++)
                    {
                        if (char.IsControl(asciiString[i]) || asciiString[i] == 0x7F) // Check if the character is a control character or DEL, 0x7F is DEL
                        {
                            hexDump.Append('.'); // replace control characters with a dot
                        }
                        else
                        {
                            hexDump.Append(asciiString[i]);
                        }
                    }
                }
            }
            return hexDump.ToString();
        }
        
        /// <summary>
        /// This method prints the information about the ARP packet.
        /// We need this method because the ARP packet has different fields
        /// than the other packets.
        /// </summary>
        /// <param name="arpInfo"></param>
        private static void PrintArpInfo(ArpInfo arpInfo)
        {
            Console.WriteLine($"timestamp: {arpInfo.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss:fffzzz")}");
            Console.WriteLine($"sender IP: {arpInfo.SenderIp}");
            Console.WriteLine($"sender MAC: {arpInfo.SenderMac}");
            Console.WriteLine($"target IP: {arpInfo.TargetIp}");
            Console.WriteLine($"target MAC: {arpInfo.TargetMac}");
            Console.WriteLine($"operation: {arpInfo.Operation}");
            Console.WriteLine($"protocol: {arpInfo.Protocol}");
            Console.WriteLine();
            Console.WriteLine(arpInfo.HexDump);
            Console.WriteLine();
            Console.WriteLine();
        }
        
        /// <summary>
        /// This method is called when the user presses Ctrl + C.
        /// It sets the flag to stop the program.
        /// </summary>
        protected static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            // Set the flag to stop the program
            _exitRequested = true;

            // Предотвращаем завершение программы по умолчанию
            e.Cancel = true;
        }
    }
}