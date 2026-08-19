# PCAP Story

A privacy-conscious command-line tool for analyzing PCAP and PCAPNG network capture files with C#, .NET, and TShark.

> Current status: Working MVP

## Overview

PCAP Story transforms raw packet-capture data into a simple, readable network summary. It is designed as a small cybersecurity and networking project with privacy and secure local processing in mind.

The application currently displays:

- Total number of captured packets
- Most frequently observed protocols
- Top source IP addresses
- Top destination IP addresses
- Most frequently used destination ports

## Privacy by Design

- Capture files are processed locally on the user's computer.
- The application does not upload packet data to an external service.
- Personal `.pcap` and `.pcapng` files are excluded from Git through `.gitignore`.
- No private network capture is included in this repository.

## Technologies

- C#
- .NET 10
- TShark / Wireshark
- Git and GitHub

## Requirements

The current version requires:

- Windows
- .NET 10 SDK
- Wireshark with TShark installed

The expected TShark path is:

```text
C:\Program Files\Wireshark\tshark.exe
```

## Getting Started

Clone the repository:

```powershell
git clone https://github.com/stef675/pcap-story.git
cd pcap-story
```

Run the analyzer:

```powershell
dotnet run --project .\PcapStory.Analyzer\PcapStory.Analyzer.csproj
```

When prompted, enter the full path of an authorized PCAP or PCAPNG file:

```text
C:\path\to\capture.pcapng
```

## Project Structure

```text
pcap-story
├── PcapStory.Analyzer
│   ├── PcapStory.Analyzer.csproj
│   └── Program.cs
├── .gitignore
└── README.md
```

## Security Measures

The program:

- Validates that the selected file exists
- Accepts only `.pcap` and `.pcapng` files
- Uses `ProcessStartInfo.ArgumentList` when calling TShark
- Avoids building executable commands from raw user input
- Does not modify the original capture file

## Roadmap

Planned improvements include:

- Exporting analysis results to JSON
- Detecting possible port-scanning patterns
- Adding IPv6 analysis
- Creating an ASP.NET Core API
- Building a React dashboard
- Supporting configurable TShark paths
- Adding a safe public demonstration capture

## Ethical Use

Analyze only network captures that you own or have explicit permission to inspect. This project is intended for education, defensive security, and authorized network analysis.

## Author

Built as part of a practical cybersecurity and application-development portfolio.
