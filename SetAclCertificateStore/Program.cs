using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace SetAclCertificateStore
{
    internal class Program
    {
        static void Main(string[] args)
        {
            X509Store store = new("WebHosting", StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            try
            {
                FindPrivateKey FindPrivateKey = new();

                List<string> fullControl = new List<string>(new[] { "iis_iusrs", "administrators" });

                X509Certificate2Collection certificates = store.Certificates;

                if(store.Certificates.Count > 0)
                foreach (X509Certificate2 certificate in certificates)
                {
                    Console.WriteLine("------------------> Start ACL Process");
                    Console.WriteLine("Subject: " + certificate.Subject);
                    Console.WriteLine("Issuer: " + certificate.Issuer);
                    Console.WriteLine("Thumbprint: " + certificate.Thumbprint);
                    Console.WriteLine("Valid from: " + certificate.NotBefore);
                    Console.WriteLine("Valid until: " + certificate.NotAfter);
                    Console.WriteLine();

                    var file = FindPrivateKey.Find(certificate);

                    SetAcl(file, fullControl);
                     Console.WriteLine("--------------> Finish ACL Process");
                }
                else
                    Console.WriteLine($"No certificate found in {store.Name}");
            }
            finally
            {
                store.Close();
            }

            Console.ReadLine();
        }

        private static void SetAcl(FileInfo? file, List<string> fullControl)
        {
            try
            {
                if (file != null)
                {                                      
                    Console.WriteLine($"Private key found at {file.FullName}");
                                      
                    var fs = new FileSecurity(file.FullName, AccessControlSections.All);
                    foreach (var account in fullControl)
                    {
                        try
                        {
                            var principal = new NTAccount(account);
                            fs.AddAccessRule(new FileSystemAccessRule(principal, FileSystemRights.FullControl, AccessControlType.Allow));
                            Console.WriteLine($"Add full control rights for {account}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Unable to set full control rights for {account}: {ex.Message}");
                            Console.WriteLine($"{ex}");
                        }
                    }
                    file.SetAccessControl(fs);                    
                }
                else
                {
                    Console.WriteLine("Unable to set requested ACL on private key (file not found)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unable to set requested ACL on private key: {ex}");
            }
        }
    }
}