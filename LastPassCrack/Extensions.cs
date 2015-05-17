using Fare;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LastPassCrack
{
    public static class Extensions
    {
        public static string RemovePadding(this string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            var chars = text.ToCharArray();
            var last = (int)chars.Last();
            var result = new char[chars.Length - last];
            Array.Copy(chars, result, chars.Length - last);
            return new String(result);
        }

        public static string GenerateUnique(this Xeger xeger, HashSet<string> previous, int maxAttempts)
        {
            var counter = 0;
            var generated = xeger.Generate();
            while (previous.Contains(generated) && counter < maxAttempts)
            {
                generated = xeger.Generate();
                counter++;
            }
            previous.Add(generated);
            return generated;
            
        }
    }
}
