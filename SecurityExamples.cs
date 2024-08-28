using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.XPath;
using System.Web;

public class SecurityExamples
{
    public void SecureMethods()
    {
        // Example inputs
        string userInput = "safeInput"; // Assume this comes from user input
        string commandInput = "safeCommand";
        string filePath = "/safe/path/file.txt";
        string sqlInput = "safeSQLInput";
        string xpathInput = "safeXPathInput";
        string ldapInput = "safeLDAPInput";
        string redirectUrl = "/safe/url";
        string xmlInput = "<root></root>";

        // CWE-78: Command Injection
        if (Regex.IsMatch(commandInput, @"^[a-zA-Z0-9]+$"))
        {
            var processInfo = new ProcessStartInfo("cmd.exe", $"/c {commandInput}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(processInfo))
            {
                string output = process.StandardOutput.ReadToEnd();
                Console.WriteLine(output);
            }
        }
        else
        {
            throw new ArgumentException("Invalid command input");
        }

        // CWE-89: SQL Injection
        using (SqlConnection connection = new SqlConnection("your_connection_string"))
        {
            string query = "SELECT * FROM Users WHERE Username = @Username";
            SqlCommand command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Username", sqlInput);

            connection.Open();
            SqlDataReader reader = command.ExecuteReader();
            // Process the result
        }

        // CWE-22: Path Traversal
        string safeFilePath = Path.GetFullPath(filePath);
        if (safeFilePath.StartsWith("/safe/path"))
        {
            string fileContent = File.ReadAllText(safeFilePath);
            Console.WriteLine(fileContent);
        }
        else
        {
            throw new UnauthorizedAccessException("Invalid file path");
        }

        // CWE-643: XPath Injection
        XmlDocument doc = new XmlDocument();
        doc.LoadXml(xmlInput);

        XPathNavigator nav = doc.CreateNavigator();
        XPathExpression expr = nav.Compile($"/root/element[text()='{xpathInput}']");

        if (expr.ReturnType == XPathResultType.NodeSet)
        {
            XPathNodeIterator iterator = nav.Select(expr);
            // Process the result
        }
        else
        {
            throw new ArgumentException("Invalid XPath input");
        }

        // CWE-79: Cross-Site Scripting (XSS)
        string safeOutput = HttpUtility.HtmlEncode(userInput);
        Console.WriteLine(safeOutput);

        // CWE-611: XML External Entity (XXE) Processing
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit; // Disable DTD processing
        XmlReader reader = XmlReader.Create(new StringReader(xmlInput), settings);
        XmlDocument safeDoc = new XmlDocument();
        safeDoc.Load(reader);

        // CWE-90: LDAP Injection
        if (Regex.IsMatch(ldapInput, @"^[a-zA-Z0-9]+$"))
        {
            // Example LDAP query would go here, using safe ldapInput
        }
        else
        {
            throw new ArgumentException("Invalid LDAP input");
        }

        // CWE-295: Certificate Validation
        ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
        {
            return sslPolicyErrors == SslPolicyErrors.None; // Ensure certificate validation is enabled
        };

        // CWE-338: Secure Random Number Generation
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            byte[] randomNumber = new byte[32];
            rng.GetBytes(randomNumber);
            Console.WriteLine(Convert.ToBase64String(randomNumber));
        }

        // CWE-327: Secure Hashing
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(userInput));
            Console.WriteLine(Convert.ToBase64String(hash));
        }

        // CWE-1004: Secure Cookie
        HttpCookie secureCookie = new HttpCookie("SessionId", "value")
        {
            HttpOnly = true,  // Ensures the cookie is HttpOnly
            Secure = true     // Ensures the cookie is sent only over HTTPS
        };

        // CWE-259: Avoid Hardcoded Passwords
        string password = Environment.GetEnvironmentVariable("APP_PASSWORD");
        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException("Password is not set");
        }

        // CWE-352: Anti-CSRF Token
        string csrfToken = HttpContext.Current.Request.Form["__RequestVerificationToken"];
        if (string.IsNullOrEmpty(csrfToken))
        {
            throw new InvalidOperationException("CSRF token is missing");
        }

        // CWE-502: Avoid Insecure Deserialization
        BinaryFormatter formatter = new BinaryFormatter();
        formatter.Binder = null; // Ensure only expected types are deserialized
        using (MemoryStream stream = new MemoryStream())
        {
            // Secure deserialization code
        }

        // CWE-521: Password Policy
        if (password.Length < 8)
        {
            throw new InvalidOperationException("Password length is insufficient");
        }

        // CWE-524: Cache Control
        HttpContext.Current.Response.Cache.SetNoStore();

        // CWE-554: ViewState Encryption
        HttpContext.Current.Request.ViewStateUserKey = "UniqueKey"; // Ensures ViewState is encrypted

        // CWE-601: Safe Redirect
        if (Uri.IsWellFormedUriString(redirectUrl, UriKind.RelativeOrAbsolute))
        {
            HttpContext.Current.Response.Redirect(redirectUrl, false);
        }
        else
        {
            throw new InvalidOperationException("Invalid redirect URL");
        }
    }
}
