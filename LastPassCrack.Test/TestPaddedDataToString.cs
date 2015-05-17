using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LastPassCrack;

namespace TestLastpassCrack
{
    /// <summary>
    /// Summary description for TestPaddedDataToString
    /// </summary>
    [TestClass]
    public class TestPaddedDataToString
    {      

        [TestMethod]
        public void TestMethod1()
        {
            var input = new byte[] { 118, 115, 104, 79, 90, 55, 57, 77, 106, 75, 119, 65, 109, 77, 122, 67, 118, 78, 48, 48, 64, 105, 54, 78, 110, 49, 35, 98, 42, 119, 2, 2 };
            var expected = @"vshOZ79MjKwAmMzCvN00@i6Nn1#b*w";
            var actual = Tools.PaddedDataToString(input);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestMethod2()
        {
            var input = new byte[] { 37, 106, 85, 80, 51, 88, 113, 76, 82, 53, 48, 38, 115, 113, 89, 53, 89, 117, 79, 111, 48, 53, 115, 105, 78, 120, 50, 109, 80, 83, 55, 36, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };
            var expected = @"%jUP3XqLR50&sqY5YuOo05siNx2mPS7$";
            var actual = Tools.PaddedDataToString(input);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestMethod3()
        {
            var input = new byte[] { 48, 90, 104, 33, 87, 78, 71, 42, 42, 105, 104, 86, 78, 50, 66, 113, 107, 82, 88, 54, 42, 110, 52, 69, 83, 122, 87, 87, 73, 37, 55, 86, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };
            var expected = @"0Zh!WNG**ihVN2BqkRX6*n4ESzWWI%7V";
            var actual = Tools.PaddedDataToString(input);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestMethod4()
        {
            var input = new byte[] { 101,33,120,115,122,119,68,75,56,65,38,82,4,4,4,4};
            var expected = @"e!xszwDK8A&R";
            var actual = Tools.PaddedDataToString(input);
            Assert.AreEqual(expected, actual);
        }
    }
}
