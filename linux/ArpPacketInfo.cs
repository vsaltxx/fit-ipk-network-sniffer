// file: ArpInfo.cs
// author: Veranika Saltanava <xsalta01>

namespace ipk_sniffer;
/// <summary>
/// This class is responsible for storing the information in an ArpInfo object.
/// </summary>
public class ArpInfo
{
    public DateTime Timestamp { get; set; }
    public string? SenderIp { get; set; }
    public string? SenderMac { get; set; }
    public string? TargetIp { get; set; }
    public string? TargetMac { get; set; }
    public string? Operation { get; set; }
    public string? HexDump { get; set; }
    public string? Protocol { get; set; }
}