using Microsoft.ML.Trainers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Text;
using System.Threading.Tasks;
using TinyIDS.Models;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace TinyIDS.Utils
{
    public static class Filter
    {
        // Надо будет прописать умные фильтры
        public static bool ApplyPayloadSizeFilter(PacketRecord record, int maxPayloadSize)
        {
            return record.Length > maxPayloadSize;
        }

        /*
        TCP/UDP 19 - CHARGEN: Often used in reflection DDoS attacks.
        TCP/UDP 135 - Microsoft RPC: Targeted for exploits like the MSBlaster worm.
        TCP/UDP 137-139 - NetBIOS: Often used for SMB-related attacks.
        TCP/UDP 445 - Microsoft-DS (SMB): Exploited in attacks like WannaCry and EternalBlue.
        TCP 1433 - Microsoft SQL Server: Targeted by SQL injection attacks and brute force attempts.
        TCP 1720 - H.323 (VoIP): Targeted for VoIP-related attacks.
        TCP/UDP 1900 - SSDP: Used in reflection DDoS attacks.
        TCP/UDP 2323 - Telnet: Often used by IoT malware.
        TCP 4444 - Metasploit Default: Used by Metasploit's default reverse shell.
        TCP 5555 - Android Debug Bridge: Often left open on Android devices and targeted by malware.
        TCP 6666-6669 - IRC: Used by many botnets for command and control (C&C).
        TCP/UDP 11211 - Memcached: Used in reflection DDoS attacks.
        TCP/UDP 12345 - NetBus: A port used by the NetBus trojan.
        TCP 31337 - Back Orifice: A port used by the Back Orifice trojan.
        TCP 54321 - BoNeSi: Botnet Security Sandbox Indicator.
        */

        public static bool ApplySuspiciousPortFilter(PacketRecord record)
{
            int[] suspiciousPorts = { 19, 135, 137, 138, 139, 445, 1433, 1720, 1900, 2323, 4444, 5555, 6666, 6667, 6668, 6669, 11211, 12345, 31337, 54321 };

            //return suspiciousPorts.Contains(record.SourcePort.GetValueOrDefault()) ||
            //       suspiciousPorts.Contains(record.DestinationPort.GetValueOrDefault());

            return suspiciousPorts.Contains(record.DestinationPort.GetValueOrDefault());
        }

        // Checks if the entropy of the packet is abnormally high or low
        public static bool ApplyEntropyFilter(PacketRecord record, double minEntropy, double maxEntropy)
        {
            return record.Entropy < minEntropy || record.Entropy > maxEntropy;
        }

        // Checks for other common anomalies
        public static bool ApplyAnomalyFilter(PacketRecord record)
        {
            // Example anomaly: TCP packet without any flags set
            if (record.Protocol == "TCP" && !(record.SynFlag.GetValueOrDefault() ||
                                              record.AckFlag.GetValueOrDefault() ||
                                              record.FinFlag.GetValueOrDefault() ||
                                              record.RstFlag.GetValueOrDefault()))
            {
                return true;
            }

            return false;
        }
    }
}
