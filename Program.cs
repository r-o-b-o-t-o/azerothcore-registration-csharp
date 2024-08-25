using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

public class Program
{
    private const int g = 7;
    private static readonly BigInteger N = new(Convert.FromHexString("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"), true, true);

    public static void Main()
    {
        string username = "testcsharp";
        string password = "passwordhere";

        byte[] salt = GenerateSalt();
        byte[] verifier = CreateVerifier(username, password, salt);
        // Registration: insert salt and verifier into the auth database

        Debug.Assert(VerifyPassword(username, password, salt, verifier));
        // Login: select salt and verifier from the auth database for the row that matches the provided username,
        // then VerifyPassword will return true if the provided credentials match the hash from the database

        Console.WriteLine($"Username: {username}");
        Console.WriteLine($"Password: {password}");
        PrintBytes(salt, "Salt");
        PrintBytes(verifier, "Verifier");
    }

    public static byte[] CreateVerifier(string username, string password, byte[] salt)
    {
        // H(I | ":" | P)
        byte[] h = SHA1.HashData(Encoding.UTF8.GetBytes($"{username}:{password}".ToUpper()));

        // x = H(s | H(I | ":" | P))
        BigInteger x = new(SHA1.HashData(salt.Concat(h).ToArray()), true);

        // g^x mod N
        byte[] verifier = BigInteger.ModPow(g, x, N).ToByteArray();

        // Pad to 32 bytes
        if (verifier.Length < 32)
        {
            Array.Resize(ref verifier, 32);
        }

        return verifier;
    }

    public static byte[] GenerateSalt()
    {
        return RandomNumberGenerator.GetBytes(32);
    }

    public static bool VerifyPassword(string username, string password, byte[] salt, byte[] verifier)
    {
        return verifier.SequenceEqual(CreateVerifier(username, password, salt));
    }

    public static void PrintBytes(byte[] data, string label = "")
    {
        string prefix = string.IsNullOrEmpty(label) ? "" : $"{label}: ";
        Console.WriteLine(prefix + "0x" + Convert.ToHexString(data));
    }
}
