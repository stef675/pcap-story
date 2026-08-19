using System.Diagnostics;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

const string tsharkPath =
    @"C:\Program Files\Wireshark\tshark.exe";

Console.WriteLine("================================");
Console.WriteLine("         PCAP STORY");
Console.WriteLine("================================");
Console.WriteLine();

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
    Console.WriteLine("Error: Only PCAP and PCAPNG files are supported.");
    return;
}

if (!File.Exists(tsharkPath))
{
    Console.WriteLine("Error: Tshark was not found.");
    return;
}

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
        Console.WriteLine("Error: Tshark could not be started.");
        return;
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
        Console.WriteLine("Tshark analysis failed.");
        Console.WriteLine(error);
        return;
    }

    var protocolCounts = new Dictionary<string, int>();
    var sourceIpCounts = new Dictionary<string, int>();
    var destinationIpCounts = new Dictionary<string, int>();
    var destinationPortCounts = new Dictionary<string, int>();

    string[] packets = output.Split(
        new[] { "\r\n", "\n" },
        StringSplitOptions.RemoveEmptyEntries);

    foreach (string packet in packets)
    {
        string[] fields = packet.Split('\t');

        string sourceIp = GetField(fields, 1);
        string destinationIp = GetField(fields, 2);
        string protocol = GetField(fields, 3);
        string tcpPort = GetField(fields, 4);
        string udpPort = GetField(fields, 5);

        AddCount(sourceIpCounts, sourceIp);
        AddCount(destinationIpCounts, destinationIp);
        AddCount(protocolCounts, protocol);

        string destinationPort =
            !string.IsNullOrWhiteSpace(tcpPort)
                ? $"TCP/{tcpPort}"
                : !string.IsNullOrWhiteSpace(udpPort)
                    ? $"UDP/{udpPort}"
                    : string.Empty;

        AddCount(destinationPortCounts, destinationPort);
    }

    Console.WriteLine();
    Console.WriteLine("========== ANALYSIS RESULT ==========");
    Console.WriteLine($"File: {Path.GetFileName(filePath)}");
    Console.WriteLine($"Total packets: {packets.Length}");

    PrintTop("Top protocols", protocolCounts);
    PrintTop("Top source IP addresses", sourceIpCounts);
    PrintTop("Top destination IP addresses", destinationIpCounts);
    PrintTop("Top destination ports", destinationPortCounts);

    Console.WriteLine();
    Console.WriteLine("Analysis completed successfully.");
}
catch (Exception exception)
{
    Console.WriteLine();
    Console.WriteLine("Unexpected error:");
    Console.WriteLine(exception.Message);
}

static string GetField(string[] fields, int index)
{
    if (index >= fields.Length)
    {
        return string.Empty;
    }

    return fields[index].Trim();
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
        Console.WriteLine($"{item.Key,-25} {item.Value}");
    }
}