using Microsoft.Win32;
using System.Management;
using static Microsoft.Win32.Registry;

namespace bypassWin11
{
    internal class Program
    {

        static string path = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
        static string PName = "";

        public static void Main()
        {

            Check("root\\CIMV2", "SELECT * FROM Win32_Processor");
            Check("\\\\.\\ROOT\\CIMV2\\Security\\MicrosoftTpm", "SELECT * FROM Win32_Tpm");


            Console.Write("Processor Name ?: ");
            string NewName = Console.ReadLine();
            PName = NewName;

            using (RegistryKey moSetup = LocalMachine.CreateSubKey(path))
            {
                moSetup.SetValue("ProcessorNameString", PName);
            }


            Check("root\\CIMV2", "SELECT * FROM Win32_Processor");
            Check("\\\\.\\ROOT\\CIMV2\\Security\\MicrosoftTpm", "SELECT * FROM Win32_Tpm");

            // Spoof TPM2.0
            // Spoof SecureBoot ON
        }



        static void Check(string root, string win)
        {
            ManagementScope scope = new ManagementScope(root);

            ObjectQuery query = new ObjectQuery(win);

            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);

            ManagementObjectCollection queryCollection = searcher.Get();

            if (win == "SELECT * FROM Win32_Tpm")
            {

                foreach (ManagementObject m in queryCollection)
                {
                    Console.WriteLine("IsActivated_InitialValue : {0}", m["IsActivated_InitialValue"]);
                    Console.WriteLine("IsEnabled_InitialValue : {0}", m["IsEnabled_InitialValue"]);
                    Console.WriteLine("SpecVersion : {0}", m["SpecVersion"]);

                }
            }
            else
            {
                foreach (ManagementObject mo in queryCollection)
                {
                    Console.WriteLine(mo["Name"]);
                    PName = (string)mo["Name"];
                }
            }
        }
    }
}