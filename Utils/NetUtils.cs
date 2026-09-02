using CFScanner.UI;
using System.Buffers.Binary;
using CFScanner.Core;
using System.Net;

namespace CFScanner.Utils;

/// <summary>
/// Network-related utility methods: IP list shuffling, CIDR expansion, and random IP generation.
/// </summary>
public static class NetUtils
{
  
    /// <summary>
    /// Expands a CIDR notation string or single IPv4 address into an enumerable of IP addresses.
    /// Expansion is capped at <see cref="Defaults.CidrExpandCap"/> addresses to prevent
    /// excessive memory usage. A warning is printed when the cap is exceeded.
    /// </summary>
    /// <param name="input">A CIDR string (e.g., "104.16.0.0/24") or a single IPv4 address.</param>
    /// <returns>Enumerable of <see cref="IPAddress"/> objects within the range.</returns>
    public static IEnumerable<IPAddress> ExpandCidr(string input)
    {
        // ---------------------------------------------------------------------
        // 1) Single IP shortcut
        // ---------------------------------------------------------------------
        // If the input is a valid IPv4 address, return it directly
        // and skip CIDR expansion logic.
        if (IPAddress.TryParse(input, out var singleIp))
        {
            yield return singleIp;
            yield break;
        }

        // ---------------------------------------------------------------------
        // 2) CIDR parsing and validation
        // ---------------------------------------------------------------------
        // Expected format: <IPv4>/<mask>
        var parts = input.Split('/');
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out var ip) ||
            !int.TryParse(parts[1], out int mask) ||
            mask < 0 || mask > 32)
            yield break;

        // Convert IP to uint for arithmetic operations
        byte[] bytes = ip.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);

        uint start = BitConverter.ToUInt32(bytes, 0);

        // ---------------------------------------------------------------------
        // 3) CIDR expansion with safety cap
        // ---------------------------------------------------------------------
        // Calculate total number of IPs in the CIDR block.
        // ulong is used to safely handle very large ranges (e.g. /0).
        ulong totalCount = 1UL << (32 - mask);

        // Limit expansion to a configurable maximum to prevent
        // excessive memory usage and long scan times.
        uint cappedCount = (uint)Math.Min(
            totalCount,
            Defaults.CidrExpandCap);

        // ---------------------------------------------------------------------
        // 4) User warning for oversized CIDR ranges
        // ---------------------------------------------------------------------
        // Inform the user that only a subset of the CIDR will be scanned,
        // while allowing the scan to continue normally.
        if (totalCount > Defaults.CidrExpandCap)
        {
            ConsoleInterface.PrintWarning(
                    $"CIDR '{input}' contains {totalCount:N0} IPs. " +
                    $"Only the first {Defaults.CidrExpandCap:N0} IPs will be scanned."
                    , prependNewLine: true
                );
        }

        // ---------------------------------------------------------------------
        // 5) IP generation loop
        // ---------------------------------------------------------------------
        // Sequentially generate IP addresses starting from the
        // network base address, up to the capped limit.
        for (uint i = 0; i < cappedCount; i++)
        {
            var newBytes = BitConverter.GetBytes(start + i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(newBytes);

            yield return new IPAddress(newBytes);
        }
    }

    /// <summary>
    /// Generates an infinite sequence of random public IPv4 addresses, skipping private/reserved ranges
    /// and addresses excluded via the global IP filter.
    /// </summary>
    /// <returns>Enumerable of random IPAddress objects.</returns>
    public static IEnumerable<IPAddress> GenerateRandomIps()
    {
        var generator = new DeterministicRandomIpv4Generator(
            (ulong)Random.Shared.NextInt64());
        while (true)
        {
            yield return UintToIp(generator.NextPublic(GlobalContext.IpFilter));
        }
    }

    /// <summary>
    /// Generates an infinite sequence of random public IPv4 addresses from a
    /// caller-provided deterministic generator, skipping private/reserved ranges
    /// and addresses excluded via the global IP filter.
    /// </summary>
    /// <param name="generator">Pre-seeded deterministic random IPv4 generator.</param>
    /// <returns>Enumerable of random public <see cref="IPAddress"/> objects.</returns>
    public static IEnumerable<IPAddress> GenerateRandomIps(DeterministicRandomIpv4Generator generator)
    {
        while (true)
            yield return UintToIp(generator.NextPublic(GlobalContext.IpFilter));
    }


    /// <summary>
    /// Converts an <see cref="IPAddress"/> to its <see cref="uint"/> representation.
    /// Only supports IPv4 addresses.
    /// </summary>
    /// <param name="ip">The IPv4 address to convert.</param>
    /// <returns>Unsigned 32-bit integer representation of the address.</returns>
    public static uint IpToUint(IPAddress ip)
    {
        Span<byte> b = stackalloc byte[4];
        if (!ip.TryWriteBytes(b, out int n) || n != 4)
            throw new NotSupportedException("Only IPv4 supported in compact mode.");
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    /// <summary>
    /// Converts a <see cref="uint"/> back to an <see cref="IPAddress"/>.
    /// </summary>
    /// <param name="v">Unsigned 32-bit integer representation of an IPv4 address.</param>
    /// <returns>The corresponding <see cref="IPAddress"/>.</returns>
    public static IPAddress UintToIp(uint v)
    {
        Span<byte> b = [(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];
        return new IPAddress(b);
    }

    /// <summary>
    /// Shuffles the first <paramref name="count"/> elements of a <see cref="uint"/> array
    /// in-place using the Fisher-Yates algorithm with the shared random generator.
    /// </summary>
    /// <param name="arr">Array to shuffle.</param>
    /// <param name="count">Number of elements to shuffle (from the beginning).</param>
    public static void Shuffle(uint[] arr, int count)
    {
        var rng = Random.Shared;
        for (int i = count - 1; i > 0; i--)
        {
            int j = rng.Next(i + 1);
            (arr[i], arr[j]) = (arr[j], arr[i]);
        }
    }

    /// <summary>
    /// Shuffles the first <paramref name="count"/> elements of a <see cref="uint"/> array
    /// in-place using the Fisher-Yates algorithm with a deterministic random generator.
    /// Used for reproducible resume of shuffled finite-mode scans.
    /// </summary>
    /// <param name="arr">Array to shuffle.</param>
    /// <param name="count">Number of elements to shuffle (from the beginning).</param>
    /// <param name="seed">Seed for the deterministic random generator.</param>
    public static void Shuffle(uint[] arr, int count, ulong seed)
    {
        var rng = new DeterministicRandomIpv4Generator(seed);
        for (int i = count - 1; i > 0; i--)
        {
            int j = (int)(rng.NextUInt32() % (uint)(i + 1));
            (arr[i], arr[j]) = (arr[j], arr[i]);
        }
    }
}
