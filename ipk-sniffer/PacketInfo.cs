// file: PacketInfo.cs
// author: Veranika Saltanava <xsalta01>


namespace ipk_sniffer;

/// <summary>
/// This class is responsible for storing the information in a PacketInfo object.
/// </summary>
public class PacketInfo
{
    public DateTime Timestamp { get; set; }
    public string? SrcMac { get; set; }
    public string? DstMac { get; set; }
    public int FrameLength { get; set; }
    public string? SrcIp { get; set; }
    public string? DstIp { get; set; }
    public int SrcPort { get; set; }
    public int DstPort { get; set; }
    public string? HexDump { get; set; }
    public string? Protocol { get; set; }
}


