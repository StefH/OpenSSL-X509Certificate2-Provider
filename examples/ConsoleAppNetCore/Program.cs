using System;

namespace ConsoleAppNetCore
{
    class Program
    {
        static void Main(string[] args)
        {
            Demo.TestX509Certificate2();
            Console.WriteLine(new string('-', 80));
            //Demo.TestX509Certificate2WithRsa();
            //Console.WriteLine(new string('-', 80));
            ////Demo.TestX509Certificate2WithEncryptedPrivateKey();
            //Console.WriteLine(new string('-', 80));
            //Demo.TestPrivateKey();
            //Console.WriteLine(new string('-', 80));
            //Demo.TestPrivateRsaKey();
        }
    }
}