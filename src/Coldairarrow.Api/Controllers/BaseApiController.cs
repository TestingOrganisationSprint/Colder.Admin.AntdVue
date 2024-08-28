using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Coldairarrow.Api
{
    /// <summary>
    /// 对外接口基控制器
    /// </summary>
    [ApiController]
    public class BaseApiController : BaseController
    {
        // CWE-78: Command Injection - Validate dynamic value passed to command execution
        public void ExecuteCommand(string userInput)
        {
            // Validate input to avoid injection
            if (!IsValidInput(userInput))
            {
                throw new ArgumentException("Invalid input");
            }

            System.Diagnostics.Process.Start("cmd.exe", $"/c {userInput}");
        }

        // CWE-89: SQL Injection - Validate user-supplied input in dynamic SQL query
        public void ExecuteSql(string userInput)
        {
            string query = $"SELECT * FROM Users WHERE Name = '{userInput}'";
            // Use parameterized queries to avoid SQL injection
            // SqlCommand command = new SqlCommand("SELECT * FROM Users WHERE Name = @name");
            // command.Parameters.AddWithValue("@name", userInput);
        }

        // CWE-643: XPath Injection - Validate dynamic value passed to XPath query
        public void ExecuteXPath(string userInput)
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml("<root><user name='JohnDoe'/></root>");
            string xpath = $"//user[@name='{userInput}']";

            // Use XmlDocument.SelectSingleNode with parameters to avoid XPath injection
            XmlNode userNode = xmlDoc.SelectSingleNode(xpath);
        }

        // CWE-611: XXE - Ensure XML parser is configured to avoid XXE
        public void ParseXml(string xmlInput)
        {
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit
            };

            using (XmlReader reader = XmlReader.Create(new StringReader(xmlInput), settings))
            {
                while (reader.Read())
                {
                    // Process XML
                }
            }
        }

        // CWE-79: Cross-Site Scripting (XSS) - Validate user input before rendering in the response
        public IActionResult DisplayUserInput(string userInput)
        {
            // Ensure the input is encoded to prevent XSS
            return Content(System.Net.WebUtility.HtmlEncode(userInput));
        }

        // CWE-90: LDAP Injection - Validate dynamic value passed to LDAP query
        public void ExecuteLdapQuery(string userInput)
        {
            string ldapQuery = $"(cn={userInput})";
            // Ensure LDAP input is properly escaped or use a safe LDAP library
        }

        // CWE-295: Certificate Validation - Do not disable certificate validation
        public void MakeHttpsRequest(string url)
        {
            System.Net.Http.HttpClientHandler handler = new System.Net.Http.HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => sslPolicyErrors == System.Net.Security.SslPolicyErrors.None
            };

            using (var client = new System.Net.Http.HttpClient(handler))
            {
                var response = client.GetAsync(url).Result;
            }
        }

        // CWE-327: Weak Hashing - Avoid MD5 or SHA1, use SHA256 or stronger
        public string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hash);
            }
        }

        // CWE-1004: Set HttpOnly flag on cookies
        public void SetCookie(HttpResponse response, string cookieValue)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true
            };
            response.Cookies.Append("MyCookie", cookieValue, cookieOptions);
        }

        // CWE-259: Avoid Hardcoded Passwords
        private string GetDatabasePassword()
        {
            // Retrieve password securely, do not hardcode
            return Environment.GetEnvironmentVariable("DB_PASSWORD");
        }

        // CWE-284: Ensure proper authorization on controller methods
        [Authorize]
        public IActionResult SecureAction()
        {
            // Only authorized users can access this action
            return Ok("Secure data");
        }

        // CWE-352: Anti-forgery token is missing
        [ValidateAntiForgeryToken]
        public IActionResult SubmitForm()
        {
            // Process form data
            return Ok("Form submitted");
        }

        // CWE-502: Avoid Deserializing Untrusted Data
        public object DeserializeData(string data)
        {
            var serializer = new System.Web.Script.Serialization.JavaScriptSerializer();
            // Ensure data is trusted or validated before deserialization
            return serializer.Deserialize<object>(data);
        }

        // CWE-521: Enforce minimum password length
        public void RegisterUser(string password)
        {
            if (password.Length < 8)
            {
                throw new ArgumentException("Password must be at least 8 characters long");
            }

            // Proceed with registration
        }

        // CWE-524: Avoid caching sensitive information
        [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
        public IActionResult SensitiveDataAction()
        {
            return Ok("Sensitive data");
        }

        // CWE-554: Set viewStateEncryptionMode to Always
        public void ConfigureViewState()
        {
            ViewStateEncryptionMode = System.Web.UI.ViewStateEncryptionMode.Always;
        }

        // CWE-614: Set Secure flag on cookies
        public void SecureCookie(HttpResponse response)
        {
            var cookieOptions = new CookieOptions
            {
                Secure = true,
                HttpOnly = true
            };
            response.Cookies.Append("SecureCookie", "value", cookieOptions);
        }
    }
}
