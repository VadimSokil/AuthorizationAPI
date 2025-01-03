using AuthorizationAPI.Interfaces;
using AuthorizationAPI.Models;
using MySql.Data.MySqlClient;
using MimeKit;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Gmail.v1;
using Google.Apis.Gmail.v1.Data;
using Google.Apis.Services;
using Newtonsoft.Json;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Util;

namespace AuthorizationAPI.Services
{
    public class AuthorizationService : IAuthorizationService
    {
        private readonly string _connectionString;
        private readonly Dictionary<string, string> _sqlRequests;
        private static string ApplicationName = "FurniroomMailSystem";
        private static string TokenPath = Path.Combine(Directory.GetCurrentDirectory(), "GmailAPI", "token.json");
        private static string CredPath = Path.Combine(Directory.GetCurrentDirectory(), "GmailAPI", "credentials.json");

        public AuthorizationService(string connectionString, Dictionary<string, string> sqlRequests)
        {
            _connectionString = connectionString;
            _sqlRequests = sqlRequests;
        }

        public bool CheckEmailExists(string email)
        {
            using (var connection = new MySqlConnection(_connectionString))
            {
                connection.Open();

                using (var command = new MySqlCommand(_sqlRequests["EmailCheck"], connection))
                {
                    command.Parameters.AddWithValue("@Email", email);

                    var result = Convert.ToInt32(command.ExecuteScalar());
                    return result > 0;
                }
            }
        }

        public bool AddNewUser(RegisterModel register)
        {
            using (var connection = new MySqlConnection(_connectionString))
            {
                connection.Open();

                using (var command = new MySqlCommand(_sqlRequests["AddNewUser"], connection))
                {
                    command.Parameters.AddWithValue("@UserId", register.user_id);
                    command.Parameters.AddWithValue("@Email", register.email);
                    command.Parameters.AddWithValue("@Pass", register.pass);
                    command.Parameters.AddWithValue("@FirstName", register.first_name);
                    command.Parameters.AddWithValue("@SecondName", register.second_name);
                    command.Parameters.AddWithValue("@PhoneNumber", register.phone_number);
                    command.Parameters.AddWithValue("@Location", register.location);

                    int rowsAffected = command.ExecuteNonQuery();
                    return rowsAffected > 0;
                }
            }
        }

        public int GenerateVerificationCode(string email)
        {
            Random random = new Random();
            int verificationCode = random.Next(1000, 9999);

            try
            {
                SendEmail(email, verificationCode);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при отправке письма: {ex.Message}");
                throw;
            }

            return verificationCode;
        }

        private void SendEmail(string recipientEmail, int verificationCode)
        {
            var service = GetGmailService();

            if (service == null)
            {
                throw new Exception("Не удалось авторизоваться для отправки электронной почты.");
            }

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("Furniroom", "vadimsokil.work@gmail.com"));
            message.To.Add(new MailboxAddress("", recipientEmail));
            message.Subject = "Secure code";
            message.Body = new TextPart("plain")
            {
                Text = $"Hi, your code: {verificationCode}"
            };

            var gmailMessage = new Message
            {
                Raw = Base64UrlEncode(message)
            };

            service.Users.Messages.Send(gmailMessage, "me").Execute();
        }

        private GmailService GetGmailService()
        {
            var clientSecrets = JsonConvert.DeserializeObject<ClientSecrets>(File.ReadAllText(CredPath));
            var token = JsonConvert.DeserializeObject<TokenResponse>(File.ReadAllText(TokenPath));

            // Проверяем срок действия токена
            if (token.IsExpired(Google.Apis.Util.SystemClock.Default))
            {
                // Создаём поток для обновления токена
                var flow = new GoogleAuthorizationCodeFlow(
                    new GoogleAuthorizationCodeFlow.Initializer
                    {
                        ClientSecrets = clientSecrets
                    });

                token = flow.RefreshTokenAsync("user", token.RefreshToken, CancellationToken.None).Result;

                // Перезаписываем обновлённый токен в файл
                File.WriteAllText(TokenPath, JsonConvert.SerializeObject(token));
            }

            var credential = new UserCredential(
                new GoogleAuthorizationCodeFlow(
                    new GoogleAuthorizationCodeFlow.Initializer
                    {
                        ClientSecrets = clientSecrets
                    }),
                "user",
                token);

            return new GmailService(new BaseClientService.Initializer
            {
                HttpClientInitializer = credential,
                ApplicationName = ApplicationName
            });
        }



        private string Base64UrlEncode(MimeMessage message)
        {
            using (var memoryStream = new MemoryStream())
            {
                message.WriteTo(memoryStream);
                return Convert.ToBase64String(memoryStream.ToArray())
                    .Replace('+', '-')
                    .Replace('/', '_')
                    .TrimEnd('=');
            }
        }

        public string ResetPassword(string email)
        {
            using (var connection = new MySqlConnection(_connectionString))
            {
                connection.Open();

                // Проверяем наличие почты в базе данных
                using (var checkCommand = new MySqlCommand(_sqlRequests["EmailCheck"], connection))
                {
                    checkCommand.Parameters.AddWithValue("@Email", email);

                    var result = Convert.ToInt32(checkCommand.ExecuteScalar());
                    if (result <= 0)
                    {
                        return string.Empty; // Почта не найдена
                    }
                }

                // Генерация нового пароля
                const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                Random random = new Random();
                string newPassword = new string(Enumerable.Repeat(chars, 8)
                    .Select(s => s[random.Next(s.Length)]).ToArray());

                // Обновление пароля в базе данных
                using (var updateCommand = new MySqlCommand(_sqlRequests["ResetPassword"], connection))
                {
                    updateCommand.Parameters.AddWithValue("@Email", email);
                    updateCommand.Parameters.AddWithValue("@Password", newPassword);

                    int rowsAffected = updateCommand.ExecuteNonQuery();
                    if (rowsAffected <= 0)
                    {
                        return string.Empty; // Ошибка обновления пароля
                    }
                }

                var service = GetGmailService();
                if (service != null)
                {
                    var message = new Message
                    {
                        Raw = Base64UrlEncode(CreateResetPasswordMessage(email, newPassword))
                    };

                    service.Users.Messages.Send(message, "me").Execute();
                }

                return newPassword; // Возвращаем только пароль
            }
        }

        private MimeMessage CreateResetPasswordMessage(string email, string newPassword)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("Furniroom", "vadimsokil.work@gmail.com"));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = "Reset password";
            message.Body = new TextPart("plain")
            {
                Text = $"Hi, your new password: {newPassword}"
            };

            return message;
        }

        public string Login(LoginModel loginModel)
        {
            using (var connection = new MySqlConnection(_connectionString))
            {
                connection.Open();

                using (var command = new MySqlCommand(_sqlRequests["Login"], connection))
                {
                    command.Parameters.AddWithValue("@Email", loginModel.email);
                    command.Parameters.AddWithValue("@Password", loginModel.password);

                    var result = Convert.ToInt32(command.ExecuteScalar());
                    if (result > 0)
                    {
                        return "Login successful";
                    }
                    else
                    {
                        return "Invalid email or password";
                    }
                }
            }
        }
    }
}
