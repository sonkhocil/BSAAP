using Bsaap.ForensicLog.Engine;
using Xunit;

namespace Bsaap.ForensicLog.Tests;

public class MerkleTreeTests
{
    // Published transparency-dev/merkle testonly/constants.go vectors.
    // RFC 9162 §2.1.3 uses the same MTH as RFC 6962.
    [Theory]
    [InlineData(0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData(1, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")]
    [InlineData(2, "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125")]
    [InlineData(3, "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77")]
    [InlineData(4, "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7")]
    [InlineData(5, "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4")]
    [InlineData(6, "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef")]
    [InlineData(7, "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c")]
    [InlineData(8, "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328")]
    public void MatchesPublishedReferenceRoots(int size, string root)
    {
        string[] leaves = ["", "00", "10", "2021", "3031", "40414243",
            "5051525354555657", "606162636465666768696a6b6c6d6e6f"];
        Assert.Equal(Convert.FromHexString(root),
            Rfc9162MerkleTree.CalculateRfc9162MerkleRoot(leaves.Take(size).Select(Convert.FromHexString).ToArray()));
    }
}
