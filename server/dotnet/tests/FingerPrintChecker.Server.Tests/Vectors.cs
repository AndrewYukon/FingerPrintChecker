using System.Text.Json;
using Xunit;

namespace FingerPrintChecker.Server.Tests;

internal static class Vectors
{
    public static JsonElement Load(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "test-vectors", name)))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        using var doc = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(dir!.FullName, "test-vectors", name)));
        return doc.RootElement.Clone();
    }

    /// <summary>Structural JSON equality (object key order and number spelling do not matter).</summary>
    public static bool JsonEq(JsonElement a, JsonElement b)
    {
        if (a.ValueKind != b.ValueKind)
        {
            return false;
        }

        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                var pa = a.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                var pb = b.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                return pa.Count == pb.Count && pa.All(kv => pb.TryGetValue(kv.Key, out var o) && JsonEq(kv.Value, o));
            case JsonValueKind.Array:
                var la = a.EnumerateArray().ToList();
                var lb = b.EnumerateArray().ToList();
                return la.Count == lb.Count && la.Zip(lb).All(z => JsonEq(z.First, z.Second));
            case JsonValueKind.String:
                return a.GetString() == b.GetString();
            case JsonValueKind.Number:
                return a.GetDecimal() == b.GetDecimal();
            default:
                return true;
        }
    }
}
