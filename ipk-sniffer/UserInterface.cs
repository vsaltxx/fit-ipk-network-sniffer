// file: UserInterface.cs
// author: Veranika Saltanava <xsalta01>

using SharpPcap;

namespace ipk_sniffer;

/// <summary>
/// This class is responsible for parsing command line arguments, creating the filter string,
/// and displaying help messages.
/// </summary>
public class UserInterface
{
    public string? InterfaceName { get; private set; }
    public List<string> ProtocolFilters { get; } = new List<string>();
    public List<string> PortFilters { get; } = new List<string>();
    public List<string> TcpOrUdp { get; } = new List<string>();
    public int NumPackets { get; private set; } = 1;
    public string Filter { get; set; } = string.Empty;
    
    /// <summary>
    /// This method parses the command line arguments and sets the appropriate fields
    /// in the UserInterface class.
    /// </summary>
    public void ParseCommandLineArgs(string[] args)
    {
        if (args.Length == 1)
        {
            DisplayHelp();
            return;
        }

        // Skip the first argument, which is the program name
        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];
            switch (arg)
            {
                case "-i":
                case "--interface":
                    // interface name
                    if (i + 1 < args.Length)
                    {
                        InterfaceName = args[i++ + 1];
                    }
                    if (args.Length == 2)
                    {
                        DisplayAllDevices();
                        return;
                    }
                    break;
                case "-p":
                case "--port":
                    // port number
                    if (i + 1 < args.Length)
                    {
                        PortFilters.Add($"port {args[i++ + 1]}");
                    }
                    break;
                case "--port-destination":
                    // destination port number
                    if (i + 1 < args.Length)
                    {
                        PortFilters.Add($"dst port {args[i++ + 1]}");
                    }
                    break;
                case "--port-source":
                    // source port number
                    if (i + 1 < args.Length)
                    {
                        PortFilters.Add($"src port {args[i++ + 1]}");
                    }
                    break;
                case "-n":
                    // number of packets
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out int num))
                    {
                        NumPackets = num;
                        i++; 
                    }
                    break;
                case "-t":
                case "--tcp":
                    // TCP protocol filter
                    TcpOrUdp.Add("tcp");
                    break;
                case "-u":
                case "--udp":
                    // UDP protocol filter
                    TcpOrUdp.Add("udp");
                    break;
                case "--icmp4":
                    // ICMPv4 protocol filter
                    ProtocolFilters.Add("icmp");
                    break;
                case "--icmp6":
                    // ICMPv6 protocol filter
                    ProtocolFilters.Add("icmp6");
                    break;
                case "--arp":
                    // ARP protocol filter
                    ProtocolFilters.Add("arp");
                    break;
                case "--ndp":
                    // NDP protocol filter
                    ProtocolFilters.Add("icmp6 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137)");
                    break;
                case "--igmp":
                    // IGMP protocol filter
                    ProtocolFilters.Add("igmp");
                    break;
                case "--mld":
                    // MLD protocol filter
                    ProtocolFilters.Add("icmp6 and (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132 or icmp[6] == 143)");
                    break;
                case "-h":
                case "--help":
                    // display help
                    DisplayHelp();
                    return;
                default:
                    // unknown argument
                    Console.WriteLine($"Unknown argument: {arg}");
                    Environment.Exit(1);
                    return;
            }
        }
        
        // if the port is specified, the protocol tcp or udp must be specified
        if ((PortFilters.Count != 0) && (TcpOrUdp.Count == 0))
        {
            Console.WriteLine("Error: Port arguments can only be specified if --tcp or --udp is also specified.");
            Environment.Exit(1);
            return;
        }
        
        // Build the filter string
        if (PortFilters. Count > 0)
            Filter = string.Join("and", PortFilters);
        
        if (TcpOrUdp.Count > 0 && Filter.Length > 0)
        {
            Filter += " and " + "(" + string.Join(" or ", TcpOrUdp) + ")";
        }
        else 
        {
            Filter += string.Join(" or ", TcpOrUdp);
        }
        
        if (ProtocolFilters.Count > 0 && Filter.Length > 0)
        {
            Filter += " or " + string.Join(" or ", ProtocolFilters);
        }
        else
        {
            Filter += string.Join(" or ", ProtocolFilters);
        }
    }

    /// <summary>
    /// This method displays all available network interfaces on the machine.
    /// </summary>
    private void DisplayAllDevices()
    {
        var devices = CaptureDeviceList.Instance;
        if (devices.Count < 1)
        {
            Console.WriteLine("No interface found on this machine");
            return;
        }

        foreach (var dev in devices)
        {
            Console.WriteLine(dev.Name);
        }
    }

    /// <summary>
    /// This method displays the help message.
    /// </summary>
    private void DisplayHelp()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("./ipk-sniffer [-i interface | --interface interface] {-p|--port port [--tcp|-t] [--udp|-u]} [--icmp4] [--icmp6] [--arp] [--ndp] [--igmp] [--mld] {-n num}");
        Console.WriteLine("Options:");
        Console.WriteLine("-i, --interface\t\tSpecify network interface to capture packets from");
        Console.WriteLine("-p, --port\t\tSpecify port to filter packets by");
        Console.WriteLine("-n\t\t\tSpecify number of packets to display");
        Console.WriteLine("-h, --help\t\tDisplay this help message");
    }
}
