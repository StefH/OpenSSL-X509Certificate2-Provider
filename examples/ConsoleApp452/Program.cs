using System;

namespace ConsoleApp452
{
    static class Program
    {
        static void Main(string[] args)
        {
            Demo.TestX509Certificate2();
            Console.WriteLine(new string('-', 80));
            Demo.TestPrivateKey();
        }
    }
}