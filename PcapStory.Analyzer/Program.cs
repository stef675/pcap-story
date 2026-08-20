using System.Diagnostics;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

const string tsharkPath =
    @"C:\Program Files\Wireshark\tshark.exe";

Console.WriteLine("================================");
Console.WriteLine("         PCAP STORY");
Console.WriteLine("================================");
Console.WriteLine();
Console.WriteLine("[1] Analyze an authorized PCAP file");
Console.WriteLine("[2] Run privacy-safe demo");
Console.WriteLine();

Console.Write("Choose an option: ");
string? option = Console.ReadLine()?.Trim();

if (option == "2")
{
    List<PacketInfo> demoPackets = CreateDemoPackets();

    AnalyzePackets(
        demoPackets,
        "Privacy-safe synthetic demonstration");

    return;
}

if (option != "1")
{
    Console.WriteLine("Error: Invalid option.");
    return;
}

Console.Write("Enter the path of a PCAP file: ");
string? filePath = Console.ReadLine();

if (string.IsNullOrWhiteSpace(filePath))
{
    Console.WriteLine("Error: No file path was entered.");
    return;
}

filePath = filePath.Trim().Trim('"');

if (!File.Exists(filePath))
{
    Console.WriteLine("Error: The selected file does not exist.");
    return;
}

string extension = Path.GetExtension(filePath).ToLowerInvariant();

if (extension != ".pcap" && extension != ".pcapng")
{
    Console.WriteLine(
        "Error: Only PCAP and PCAPNG files are supported.");

    return;
}

if (!File.Exists(tsharkPath))
{
    Console.WriteLine("Error: TShark was not found.");
    return;
}

List<PacketInfo>? capturedPackets =
    await ReadPacketsAsync(tsharkPath, filePath);

if (capturedPackets is null)
{
    return;
}

AnalyzePackets(
    capturedPackets,
    Path.GetFileName(filePath));

static async Task<List<PacketInfo>?> ReadPacketsAsync(
    string tsharkPath,
    string filePath)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = tsharkPath,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    startInfo.ArgumentList.Add("-r");
    startInfo.ArgumentList.Add(filePath);

    startInfo.ArgumentList.Add("-T");
    startInfo.ArgumentList.Add("fields");

    startInfo.ArgumentList.Add("-e");
    startInfo.ArgumentList.Add("frame.number");

    startInfo.ArgumentList.Add("-e");
    startInfo.ArgumentList.Add("ip.src");

    startInfo.ArgumentList.Add("-e");
    startInfo.ArgumentList.Add("ip.dst");

    startInfo.ArgumentList.Add("-e");
    startInfo.ArgumentList.Add("_ws.col.Protocol");

    startInfo.ArgumentList.Add("-e");
    startInfo.ArgumentList.Add("tcp.dstport");

    startInfo.ArgumentList.Add("-e");
    startInfo.ArgumentList.Add("udp.dstport");

    Console.WriteLine();
    Console.WriteLine("Analyzing capture...");

    try
    {
        using Process? process = Process.Start(startInfo);

        if (process is null)
        {
            Console.WriteLine(
                "Error: TShark could not be started.");

            return null;
        }

        Task<string> outputTask =
            process.StandardOutput.ReadToEndAsync();

        Task<string> errorTask =
            process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();

        string output = await outputTask;
        string error = await errorTask;

        if (process.ExitCode != 0)
        {
            Console.WriteLine("TShark analysis failed.");
            Console.WriteLine(error);

            return null;
        }

        var packets = new List<PacketInfo>();

        string[] lines = output.Split(
            new[] { "\r\n", "\n" },
            StringSplitOptions.RemoveEmptyEntries);

        foreach (string line in lines)
        {
            string[] fields = line.Split('\t');

            string sourceIp =
                FirstValue(GetField(fields, 1));

            string destinationIp =
                FirstValue(GetField(fields, 2));

            string protocol =
                FirstValue(GetField(fields, 3));

            string tcpPort =
                FirstValue(GetField(fields, 4));

            string udpPort =
                FirstValue(GetField(fields, 5));

            string transport = string.Empty;
            string destinationPort = string.Empty;

            if (!string.IsNullOrWhiteSpace(tcpPort))
            {
                transport = "TCP";
                destinationPort = tcpPort;
            }
            else if (!string.IsNullOrWhiteSpace(udpPort))
            {
                transport = "UDP";
                destinationPort = udpPort;
            }

            packets.Add(
                new PacketInfo(
                    sourceIp,
                    destinationIp,
                    protocol,
                    transport,
                    destinationPort));
        }

        return packets;
    }
    catch (Exception exception)
    {
        Console.WriteLine();
        Console.WriteLine("Unexpected error:");
        Console.WriteLine(exception.Message);

        return null;
    }
}

static void AnalyzePackets(
    IReadOnlyCollection<PacketInfo> packets,
    string sourceName)
{
    var protocolCounts = new Dictionary<string, int>();
    var sourceIpCounts = new Dictionary<string, int>();
    var destinationIpCounts = new Dictionary<string, int>();
    var destinationPortCounts =
        new Dictionary<string, int>();

    foreach (PacketInfo packet in packets)
    {
        AddCount(protocolCounts, packet.Protocol);
        AddCount(sourceIpCounts, packet.SourceIp);
        AddCount(
            destinationIpCounts,
            packet.DestinationIp);

        if (!string.IsNullOrWhiteSpace(
                packet.DestinationPort))
        {
            string portName =
                $"{packet.Transport}/{packet.DestinationPort}";

            AddCount(destinationPortCounts, portName);
        }
    }

    Console.WriteLine();
    Console.WriteLine(
        "========== ANALYSIS RESULT ==========");

    Console.WriteLine($"Source: {sourceName}");
    Console.WriteLine($"Total packets: {packets.Count}");

    PrintTop("Top protocols", protocolCounts);
    PrintTop("Top source IP addresses", sourceIpCounts);

    PrintTop(
        "Top destination IP addresses",
        destinationIpCounts);

    PrintTop(
        "Top destination ports",
        destinationPortCounts);

    PrintSecurityFindings(packets);

    Console.WriteLine();
    Console.WriteLine(
        "Analysis completed successfully.");
}

static void PrintSecurityFindings(
    IReadOnlyCollection<PacketInfo> packets)
{
    const int portScanThreshold = 10;

    var possiblePortScans = packets
        .Where(packet =>
            !string.IsNullOrWhiteSpace(packet.SourceIp) &&
            !string.IsNullOrWhiteSpace(
                packet.DestinationIp) &&
            !string.IsNullOrWhiteSpace(
                packet.DestinationPort))
        .GroupBy(packet => new
        {
            packet.SourceIp,
            packet.DestinationIp
        })
        .Select(group => new
        {
            group.Key.SourceIp,
            group.Key.DestinationIp,

            Ports = group
                .Select(packet =>
                    packet.DestinationPort)
                .Distinct()
                .ToList()
        })
        .Where(result =>
            result.Ports.Count >= portScanThreshold)
        .ToList();

    Console.WriteLine();
    Console.WriteLine("--- Security findings ---");

    if (possiblePortScans.Count == 0)
    {
        Console.WriteLine(
            "[INFO] No obvious port-scanning pattern detected.");

        return;
    }

    foreach (var scan in possiblePortScans)
    {
        Console.WriteLine(
            $"[HIGH] Possible port scan: " +
            $"{scan.SourceIp} contacted " +
            $"{scan.Ports.Count} different ports on " +
            $"{scan.DestinationIp}.");
    }
}

static List<PacketInfo> CreateDemoPackets()
{
    var packets = new List<PacketInfo>();

    // Documentation-only addresses from TEST-NET ranges.
    for (int port = 20; port < 35; port++)
    {
        packets.Add(
            new PacketInfo(
                "192.0.2.10",
                "198.51.100.20",
                "TCP",
                "TCP",
                port.ToString()));
    }

    for (int number = 0; number < 25; number++)
    {
        packets.Add(
            new PacketInfo(
                "203.0.113.5",
                "198.51.100.25",
                "TLS",
                "TCP",
                "443"));
    }

    for (int number = 0; number < 10; number++)
    {
        packets.Add(
            new PacketInfo(
                "192.0.2.50",
                "198.51.100.53",
                "DNS",
                "UDP",
                "53"));
    }

    return packets;
}

static string GetField(
    string[] fields,
    int index)
{
    if (index >= fields.Length)
    {
        return string.Empty;
    }

    return fields[index].Trim();
}

static string FirstValue(string value)
{
    return value
        .Split(',', StringSplitOptions.RemoveEmptyEntries)
        .FirstOrDefault()?.Trim() ?? string.Empty;
}

static void AddCount(
    Dictionary<string, int> dictionary,
    string value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return;
    }

    if (dictionary.ContainsKey(value))
    {
        dictionary[value]++;
    }
    else
    {
        dictionary[value] = 1;
    }
}

static void PrintTop(
    string title,
    Dictionary<string, int> values)
{
    Console.WriteLine();
    Console.WriteLine($"--- {title} ---");

    if (values.Count == 0)
    {
        Console.WriteLine("No data found.");
        return;
    }

    foreach (var item in values
                 .OrderByDescending(item => item.Value)
                 .Take(5))
    {
        Console.WriteLine(
            $"{item.Key,-25} {item.Value}");
    }
}

internal sealed record PacketInfo(
    string SourceIp,
    string DestinationIp,
    string Protocol,
    string Transport,
    string DestinationPort);